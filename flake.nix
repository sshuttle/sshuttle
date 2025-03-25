{
  description = "Transparent proxy server that works as a poor man's VPN. Forwards over ssh. Doesn't require admin. Works with Linux and MacOS. Supports DNS tunneling.";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      pyproject-nix,
      uv2nix,
      pyproject-build-systems,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        inherit (nixpkgs) lib;

        pkgs = nixpkgs.legacyPackages.${system};

        python = pkgs.python312;

        workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };

        # Create package overlay from workspace.
        overlay = workspace.mkPyprojectOverlay {
          sourcePreference = "sdist";
        };

        # Extend generated overlay with build fixups
        #
        # Uv2nix can only work with what it has, and uv.lock is missing essential metadata to perform some builds.
        # This is an additional overlay implementing build fixups.
        # See:
        # - https://pyproject-nix.github.io/uv2nix/FAQ.html
        pyprojectOverrides =
          final: prev:
          # Implement build fixups here.
          # Note that uv2nix is _not_ using Nixpkgs buildPythonPackage.
          # It's using https://pyproject-nix.github.io/pyproject.nix/build.html
          let
            inherit (final) resolveBuildSystem;
            inherit (builtins) mapAttrs;

            # Build system dependencies specified in the shape expected by resolveBuildSystem
            # The empty lists below are lists of optional dependencies.
            #
            # A package `foo` with specification written as:
            # `setuptools-scm[toml]` in pyproject.toml would be written as
            # `foo.setuptools-scm = [ "toml" ]` in Nix
            buildSystemOverrides = {
              chardet.setuptools = [ ];
              colorlog.setuptools = [ ];
              python-debian.setuptools = [ ];
              pluggy.setuptools = [ ];
              pathspec.flit-core = [ ];
              packaging.flit-core = [ ];
            };

          in
          mapAttrs (
            name: spec:
            prev.${name}.overrideAttrs (old: {
              nativeBuildInputs = old.nativeBuildInputs ++ resolveBuildSystem spec;
            })
          ) buildSystemOverrides;

        pythonSet =
          (pkgs.callPackage pyproject-nix.build.packages {
            inherit python;
          }).overrideScope
            (
              lib.composeManyExtensions [
                pyproject-build-systems.overlays.default
                overlay
                pyprojectOverrides
              ]
            );

        inherit (pkgs.callPackages pyproject-nix.build.util { }) mkApplication;
        package = mkApplication {
          venv = pythonSet.mkVirtualEnv "sshuttle" workspace.deps.default;
          package = pythonSet.sshuttle;
        };
      in
      {
        packages = {
          sshuttle = package;
          default = package;
        };
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.uv
          ];
        };
      }
    );
}
