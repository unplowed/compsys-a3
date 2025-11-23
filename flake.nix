{
  description = "simple gcc flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = {nixpkgs, ...}: let
    forAllSystems = nixpkgs.lib.genAttrs [
      "aarch64-linux"
      "x86_64-linux"
      "aarch64-darwin"
      "x86_64-darwin"
    ];
  in {
    devShells = forAllSystems (
      system: let
        pkgs = import nixpkgs {inherit system;};
      in {
        default = pkgs.mkShell {
          buildInputs = with pkgs; [
            gcc
            libgcc
            valgrind
            gnumake
            lldb
            zip

            (
              python314.withPackages (pkgs:
                with pkgs; [
                  threads
                ])
            )
          ];
        };
      }
    );

    packages = forAllSystems (system: let
      pkgs = import nixpkgs {inherit system;};
    in rec {
      peer = pkgs.stdenv.mkDerivation {
        name = "peer";
        version = "0.0.1";

        src = ./src;

        phases = ["buildPhase"];

        nativeBuildInputs = [pkgs.makeWrapper];

        buildPhase = let 
          compile = [
            "peer"
            "compsys_helpers"
            "common"
            "sha256"
          ];
          filelist = builtins.concatStringsSep " " (map (x: "/build/${x}.o") compile);
        in ''
          mkdir -p $out/bin
          cd $src
          ${
          builtins.concatStringsSep "\n"
            (map (x: "${pkgs.clang}/bin/clang -O1 -g -fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls -c $src/${x}.c -lpthread -lm -o /build/${x}.o") compile)
          }

          ${pkgs.clang}/bin/clang -g -fsanitize=address ${filelist} -o $out/bin/peer -lpthread -lm
          wrapProgram $out/bin/peer --set ASAN_SYMBOLIZER_PATH "${pkgs.libllvm}/bin/llvm-symbolizer"
        '';

        meta.mainProgram = "peer";
      };
      default = peer;
    });

    apps = forAllSystems (system: let
      pkgs = import nixpkgs {inherit system;};
    in {
      "zip" = let
        files = [
          "src/*.c"
          "src/*.h"
          "src/Makefile"
          "python/**/*.py"
        ];
      in {
        type = "app";
        program = toString (pkgs.writeShellScript "zip.sh" ''
          ${pkgs.zip}/bin/zip compsys-a3.zip ${builtins.concatStringsSep " " files}
        '');
      };
    });

    formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.alejandra);
  };
}
