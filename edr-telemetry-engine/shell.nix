{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "edr-telemetry-dev";
  buildInputs = with pkgs; [
    dotnet-sdk_8
    git
    curl
    wget
    jq
    libxml2
    openssl
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
}
