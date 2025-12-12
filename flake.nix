{
  description = "A flake for the epc.php script";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
  };

  outputs = { self, nixpkgs }: {
    packages.x86_64-linux = let
      pkgs = import nixpkgs { system = "x86_64-linux"; };
    in
    {
      default = pkgs.stdenv.mkDerivation {
        name = "epc";
        src = self;

        buildInputs = [
          pkgs.php
          pkgs.phpExtensions.curl
          pkgs.makeWrapper
        ];

        installPhase = ''
          mkdir -p $out/bin
          cp ${self}/epc.php $out/bin/epc.php
          makeWrapper ${pkgs.php}/bin/php $out/bin/start-server --add-flags "-S 0.0.0.0:8000 -t $out/bin"
        '';

        meta = with pkgs.lib; {
          description = "A PHP script to check the availability of a URL and compare hash values";
          license = licenses.mit;
          maintainers = with maintainers; [ suorcd ];
        };
      };
    };
  };
}