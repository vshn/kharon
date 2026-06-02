{pkgs ? import <nixpkgs> {}}:
pkgs.buildGoLatestModule {
  pname = "kharon";
  version = "1.6.1-dev2";

  src = pkgs.lib.cleanSource ./.;

  proxyVendor = true;
  vendorHash = "sha256-hRneNomGxDXprrEAPyBYIT9YxL2lefc2m8Jn8iU2JlA=";

  subPackages = ["."];

  preBuild = ''
    go generate ./...
  '';

  passthru.updateScript = pkgs.nix-update-script {};

  meta = with pkgs.lib; {
    description = "Ferries your connections safely across SSH jumphosts into private networks";
    homepage = "https://github.com/vshn/kharon";
    license = licenses.bsd3;
    mainProgram = "kharon";
  };
}
