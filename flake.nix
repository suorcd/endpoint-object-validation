{
  description = "Endpoint Object Validation - Bash script and Flask app for endpoint object validation";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
    in
    {
      # Package the bash script
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.stdenv.mkDerivation {
            name = "eov";
            src = ./.;

            buildInputs = [
              pkgs.bash
              pkgs.curl
              pkgs.drill
              pkgs.coreutils
            ];

            installPhase = ''
              mkdir -p $out/bin
              cp ${./eov.sh} $out/bin/eov.sh
              chmod +x $out/bin/eov.sh
            '';

            meta = with pkgs.lib; {
              description = "A script to check the availability of a URL and compare hash values";
              license = licenses.gpl3;
              maintainers = with maintainers; [ suorcd ];
            };
          };
        }
      );

      # Development shells
      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python = pkgs.python311;
          pythonEnv = python.withPackages (ps: with ps; [
            flask
            requests
            urllib3
            pyyaml
          ]);
        in
        {
          # Default: Flask development environment
          default = pkgs.mkShell {
            packages = [
              pythonEnv
              pkgs.gcc
              pkgs.openssl
              pkgs.libffi
              pkgs.kubectl
              pkgs.docker
              pkgs.bash
              pkgs.curl
              pkgs.drill
            ];

            shellHook = ''
              echo "🚀 Endpoint Object Validation - Flask dev environment"
              echo "Python: ${python.version}"
              echo ""
              echo "Flask quick start:"
              echo "  cd flask"
              echo "  flask --app app run --host=0.0.0.0 --port=5000"
              echo "  flask --app app run --host=0.0.0.0 --port=5000 --debug  # with hot reload"
              echo ""
              echo "Bash script:"
              echo "  ./eov.sh <URL> [--hash HASH] [--file FILE] [--hash-alg HASH_ALG]"
              echo ""
              echo "Container testing:"
              echo "  cd flask && docker build -t eov-flask:latest ."
              echo "  docker run -p 5000:5000 eov-flask:latest"
            '';

            FLASK_APP = "app.py";
          };

          # Flask-specific development environment
          flask = pkgs.mkShell {
            packages = [
              pythonEnv
              pkgs.gcc
              pkgs.openssl
              pkgs.libffi
              pkgs.kubectl
              pkgs.docker
            ];

            shellHook = ''
              echo "🚀 eov-flask EOV - Flask development environment"
              echo "Python: ${python.version}"
              echo ""
              echo "Quick start:"
              echo "  cd flask"
              echo "  flask --app app run --host=0.0.0.0 --port=5000"
              echo ""
              echo "With hot reload:"
              echo "  flask --app app run --host=0.0.0.0 --port=5000 --debug"
              echo ""
              echo "Local container testing:"
              echo "  cd flask"
              echo "  docker build -t eov-flask:latest ."
              echo "  docker run -p 5000:5000 eov-flask:latest"
              echo ""
              echo "Deployment commands:"
              echo "  cd flask && ./deploy.sh [--tailscale]"
            '';

            FLASK_APP = "app.py";
          };

          # Bash script development environment
          bash = pkgs.mkShell {
            packages = [
              pkgs.bash
              pkgs.curl
              pkgs.drill
              pkgs.coreutils
              pkgs.shellcheck
              pkgs.shfmt
            ];

            shellHook = ''
              echo "🔧 EOV Bash Script - Development environment"
              echo ""
              echo "Available tools:"
              echo "  bash, curl, drill, shellcheck, shfmt"
              echo ""
              echo "Run the script:"
              echo "  ./eov.sh <URL> [--hash HASH] [--file FILE] [--hash-alg HASH_ALG] [--debug]"
              echo ""
              echo "Lint the script:"
              echo "  shellcheck eov.sh"
              echo ""
              echo "Format the script:"
              echo "  shfmt -w eov.sh"
            '';
          };
        }
      );
    };
}