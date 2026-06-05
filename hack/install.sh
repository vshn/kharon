#!/bin/bash
# vim: et sw=2
set -eu

install_dir=${KHARON_INSTALL_DIR:-~/.local/bin}

# Add the Kharon install dir to the script's $PATH.
#
# NOTE(sg): This is required so that the script reliably finds the existing
# Kharon binary when executed through a systemd user unit. From what we've
# found so far, the systemd user daemon eventually inherits the user's custom
# PATH in some environments, possibly depending on how the user's session is
# started.
export PATH="${PATH}:${install_dir}"

version=$(kharon version 2>/dev/null| cut -d' ' -f2)
location="${install_dir}/kharon"
if [ "${version}" != "" ]; then
  location=$(which kharon)
elif [ "${version}" = "" ] && go version -m "$(which kharon)" &>/dev/null; then
  location=$(which kharon)
  version=$(go version -m "${location}" | grep -E 'mod.*kharon' | cut -f4)
fi

latest_release=$(curl -fsSL "https://api.github.com/repos/vshn/kharon/releases/latest")
latest=$(jq -r -n --argjson latest "$latest_release" '$latest.tag_name')
if [ "${version}" = "" ]; then
  echo "No Kharon found in PATH, installing ${latest} to ${location}"
elif [ "${version}" != "${latest}" ]; then
  echo "Kharon version ${version} found at ${location}, upgrading to ${latest}"
else
  echo "Kharon ${version} installed at ${location}. No update available."
  exit 0
fi

ARCH=$(uname -m)
case $ARCH in
  aarch64|arm64) ARCH="aarch64";;
  x86_64|amd64) ARCH="x86_64";;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 3
    ;;
esac

PLATFORM=$(uname -s)
case "$PLATFORM" in
  Linux*) PLATFORM="linux";;
  Darwin*) PLATFORM="darwin";;
  *)
    echo "Unsupported platform: $PLATFORM"
    exit 3
    ;;
esac

if [ "$PLATFORM" == "darwin" ] && [ "$ARCH" == "x86_64" ]; then
  echo "Kharon doesn't support macOS x86_64"
  exit 1
fi

bin_name="kharon-${PLATFORM}-${ARCH}"
asset_url=$(jq -r -n \
  --argjson "release" "$latest_release" \
  --arg bin_name "$bin_name" \
  '$release.assets[]|select(.name == $bin_name)|.browser_download_url')
asset_checksum=$(jq -r -n \
  --argjson "release" "$latest_release" \
  --arg bin_name "$bin_name" \
  '$release.assets[]|select(.name == $bin_name)|.digest|sub("sha256:"; "")')

echo "Downloading Kharon ${latest}"
download_dir=$(mktemp -d /tmp/kharon-install.XXXXXX)
echo -e "${asset_checksum} ${download_dir}/${bin_name}" > "${download_dir}/checksum.txt"
curl -fsSLO --output-dir "${download_dir}" "$asset_url"

echo "Verifying checksum of downloaded binary"
sha256sum --strict -c "${download_dir}/checksum.txt"

echo "Installing Kharon ${latest} to ${location}"
install "${download_dir}/${bin_name}" "${location}"

if [ "$PLATFORM" = "darwin" ]; then
  xattr -dr com.apple.quarantine "${location}"
  codesign -s - --deep --force "${location}"
fi
rm -r "${download_dir}"
echo "Kharon installed successfully!"
echo "Make sure to add $(dirname "${location}") to your PATH if it isn't already!"
