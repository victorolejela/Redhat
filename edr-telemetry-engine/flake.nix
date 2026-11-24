{
  description = "EDR & Identity Telemetry Auditing Engine - Development Environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.05";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f {
        pkgs = nixpkgs.legacyPackages.${system};
      });
    in
    {
      devShells = forAllSystems ({ pkgs }: {
        default = pkgs.mkShell {
          name = "edr-telemetry-dev";
          buildInputs = with pkgs; [
            # .NET SDK
            dotnet-sdk_8

            # Development tools
            git
            curl
            wget
            jq
            
            # Optional: for Windows event log simulation/testing
            libxml2
            openssl

            # Code editors & debugging
            vim
            nano
            
            # Build & package management
            pkg-config
            gnumake
          ];

          shellHook = ''
            echo "🔒 EDR Telemetry Engine - NixOS Development Environment"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            dotnet --version
            echo ""
            echo "Available commands:"
            echo "  dotnet build            - Build the solution"
            echo "  dotnet test             - Run unit tests"
            echo "  dotnet run --project src/EDRTelemetry.ConsoleApp"
            echo ""
          '';
        };
      });
    };
}
