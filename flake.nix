{
  description = "Rust build environment for net-loginer";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };

        darwinSdk = pkgs.lib.optionals pkgs.stdenv.isDarwin [
          pkgs.apple-sdk_15
        ];

        nativeBuildInputs = with pkgs; [
          makeWrapper
          pkg-config
          rustPlatform.bindgenHook
        ];

        buildInputs =
          with pkgs;
          [
            onnxruntime
            openssl
          ]
          ++ darwinSdk;

        ortEnv = {
          ORT_LIB_LOCATION = "${pkgs.onnxruntime}/lib";
          ORT_PREFER_DYNAMIC_LINK = "1";
        };
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage (
          ortEnv
          // {
            pname = "net-loginer";
            version = "0.5.1";
            src = self;

            cargoLock.lockFile = ./Cargo.lock;

            inherit nativeBuildInputs buildInputs;

            # The binary performs a real network login, so a build-time check is
            # less useful than keeping the derivation hermetic.
            doCheck = false;

            postInstall = pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
              wrapProgram "$out/bin/net-loginer" \
                --prefix DYLD_LIBRARY_PATH : "${pkgs.lib.makeLibraryPath [ pkgs.onnxruntime ]}"
            '';
          }
        );

        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.default;
        };

        devShells.default = pkgs.mkShell (
          ortEnv
          // {
            packages =
              with pkgs;
              [
                cargo
                clippy
                rustc
                rustfmt
              ]
              ++ nativeBuildInputs
              ++ buildInputs;

            shellHook = ''
              export DYLD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.onnxruntime ]}:''${DYLD_LIBRARY_PATH:-}"
              echo "Rust + ONNX Runtime shell ready. Try: cargo build --release"
            '';
          }
        );

        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
