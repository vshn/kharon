pkgname=kharon
pkgver=1.7.3
pkgrel=1
pkgdesc="Ferries your connections safely across SSH jumphosts into private networks"
arch=('x86_64' 'aarch64')
url="https://github.com/vshn/kharon"
license=('BSD-3-Clause')
depends=('openssh')
makedepends=('go')
source=("$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('SKIP')
options=('!debug')

prepare() {
  cd "$pkgname-$pkgver"
  mkdir -p build/
}

build() {
  cd "$pkgname-$pkgver"
  export CGO_CPPFLAGS="${CPPFLAGS}"
  export CGO_CFLAGS="${CFLAGS}"
  export CGO_CXXFLAGS="${CXXFLAGS}"
  export CGO_LDFLAGS="${LDFLAGS}"
  export GOFLAGS="-buildmode=pie -trimpath -mod=readonly -modcacherw"
  go generate ./...
  go build -ldflags "-linkmode=external" -o "build/$pkgname" .
}

check() {
  cd "$pkgname-$pkgver"
  go test ./...
}

package() {
  cd "$pkgname-$pkgver"
  install -Dm755 "build/$pkgname" "$pkgdir/usr/bin/$pkgname"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"

  install -dm755 "$pkgdir/usr/share/bash-completion/completions" \
                 "$pkgdir/usr/share/zsh/site-functions" \
                 "$pkgdir/usr/share/fish/vendor_completions.d"
  "./build/$pkgname" completion bash > "$pkgdir/usr/share/bash-completion/completions/$pkgname"
  "./build/$pkgname" completion zsh  > "$pkgdir/usr/share/zsh/site-functions/_$pkgname"
  "./build/$pkgname" completion fish > "$pkgdir/usr/share/fish/vendor_completions.d/$pkgname.fish"
}
