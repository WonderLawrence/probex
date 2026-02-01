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

        # Build bpf-linker from source using crane
        bpf-linker-src = pkgs.fetchFromGitHub {
          owner = "aya-rs";
          repo = "bpf-linker";
          rev = "v0.10.1";
          hash = "sha256-WFMQlaM18v5FsrsjmAl1nPGNMnBW3pjXmkfOfv3Izq0=";
        };

        # Combine LLVM dev (llvm-config) and lib (libLLVM.so) outputs
        llvm-combined = pkgs.symlinkJoin {
          name = "llvm-combined";
          paths = [
            pkgs.llvmPackages_22.llvm.dev
            pkgs.llvmPackages_22.libllvm.lib
          ];
        };

        bpf-linker-crane = pkgs.rustPlatform.buildRustPackage {
          pname = "bpf-linker";
          version = "0.10.1";
          src = bpf-linker-src;
          cargoHash = "sha256-m/mlN1EL5jYxprNXvMbuVzBsewdIOFX0ebNQWfByEHQ=";
          buildNoDefaultFeatures = true;
          buildFeatures = [ "llvm-22" ];
          doCheck = false;
          nativeBuildInputs = with pkgs; [
            clang
            pkg-config
          ];
          buildInputs = with pkgs; [
            llvmPackages_22.libllvm
            zlib
          ];
          LLVM_PREFIX = llvm-combined;
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
              bpf-linker-crane
              bpftools
              rustup
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
