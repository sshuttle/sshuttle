{
  description = "Transparent proxy server that works as a poor man's VPN. Forwards over ssh. Doesn't require admin. Works with Linux and MacOS. Supports DNS tunneling.";

  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
  inputs.poetry2nix = {
    url = "github:nix-community/poetry2nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      poetry2nix,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        p2n = import poetry2nix { inherit pkgs; };
        overrides = p2n.defaultPoetryOverrides.extend (
          self: super: {
            nh3 = super.nh3.override { preferWheel = true; };
            bump2version = super.bump2version.overridePythonAttrs (old: {
              buildInputs = (old.buildInputs or [ ]) ++ [ super.setuptools ];
            });
          }
        );

        poetry_env = p2n.mkPoetryEnv {
          python = pkgs.python3;
          projectDir = self;
          inherit overrides;
        };
        poetry_app = p2n.mkPoetryApplication {
          python = pkgs.python3;
          projectDir = self;
          inherit overrides;
        };
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages = {
          sshuttle = poetry_app;
          default = self.packages.${system}.sshuttle;
        };
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.poetry
            poetry_env
          ];
        };
      }
    );
}
