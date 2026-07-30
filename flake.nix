{
  description = "wp2shell — CVE-2026-63030 + CVE-2026-60137 research PoC (WordPress REST batch desync + WP_Query SQLi)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python3;

        wp2shell = python.pkgs.buildPythonApplication {
          pname = "wp2shell";
          version = "2.0.0";
          src = ./.;

          # PEP 621 metadata in pyproject.toml, setuptools backend.
          format = "pyproject";
          nativeBuildInputs = [ python.pkgs.setuptools ];

          # Pure standard library — no runtime dependencies.
          propagatedBuildInputs = [ ];

          doCheck = false;
          pythonImportsCheck = [ "wp2shell" "wp2shell.cli" "wp2shell.sqli" ];

          meta = with pkgs.lib; {
            description = "Research PoC for CVE-2026-63030 + CVE-2026-60137 (WordPress pre-auth SQLi chain)";
            homepage = "https://github.com/";
            license = licenses.mit;
            mainProgram = "wp2shell";
            platforms = platforms.unix;
          };
        };
      in
      {
        # nix build .#           -> ./result/bin/wp2shell
        packages.default = wp2shell;
        packages.wp2shell = wp2shell;

        # nix run .# -- check http://TARGET/
        apps.default = {
          type = "app";
          program = "${wp2shell}/bin/wp2shell";
        };
        apps.wp2shell = self.apps.${system}.default;

        # nix develop
        devShells.default = pkgs.mkShell {
          packages = [ wp2shell python pkgs.git ];
          shellHook = ''
            export PYTHONPATH="$PWD/src''${PYTHONPATH:+:$PYTHONPATH}"
            echo "wp2shell devshell ready (Python ${python.version})."
            echo "  wp2shell --help             # installed CLI"
            echo "  python -m wp2shell --help   # from ./src (live edits)"
            echo "Authorized testing only — see AUTHORIZATION.md."
          '';
        };
      });
}
