{
  description = "Related Work Flake Configuration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      nixpkgs,
      rust-overlay,
      flake-utils,
      crane,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        craneLib = crane.mkLib pkgs;
        rustToolchain = pkgs.rust-bin.selectLatestNightlyWith (
          toolchain:
          toolchain.default.override {
            extensions = [
              "rust-src"
              "llvm-tools-preview"
            ];
            targets = [ "wasm32-unknown-unknown" ];
          }
        );
        # Fetch daisyUI bundle files
        daisyui-bundle = pkgs.fetchurl {
          url = "https://github.com/saadeghi/daisyui/releases/download/v5.5.14/daisyui.mjs";
          sha256 = "sha256-ZhCaZQYZiADXoO3UwaAqv3cxiYu87LEiZuonefopRUw=";
        };
        daisyui-theme-bundle = pkgs.fetchurl {
          url = "https://github.com/saadeghi/daisyui/releases/download/v5.5.14/daisyui-theme.mjs";
          sha256 = "sha256-PPO2fLQ7eB+ROYnpmK5q2LHIoWUE+EcxYmvjC+gzgSw=";
        };
        cargoVendorDir = craneLib.vendorCargoDeps {
          src = ./.;
        };
      in
      {
        devShells.default =
          with pkgs;
          mkShell {
            packages = [
              openssl
              pkg-config
              eza
              fd
              llvmPackages.bintools
              lldb
              wasm-bindgen-cli
              binaryen
              nixd
              tailwindcss_4
              dioxus-cli
              rustToolchain
            ];
            shellHook = ''
              # Setup daisyUI vendor files
              VENDOR_DIR="vendor"
              mkdir -p "$VENDOR_DIR"
              # Copy daisyUI files from Nix store if they don't exist or are outdated
              if [ ! -f "$VENDOR_DIR/daisyui.mjs" ] || [ "${daisyui-bundle}" -nt "$VENDOR_DIR/daisyui.mjs" ]; then
                echo "Setting up daisyUI bundle files..."
                cp -f "${daisyui-bundle}" "$VENDOR_DIR/daisyui.mjs"
                cp -f "${daisyui-theme-bundle}" "$VENDOR_DIR/daisyui-theme.mjs"
                echo "daisyUI files ready in $VENDOR_DIR"
              fi
            '';
          };
      }
    );
}
