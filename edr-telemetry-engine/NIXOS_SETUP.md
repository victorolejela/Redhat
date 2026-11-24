# EDR & Identity Telemetry Engine - NixOS Setup Guide

## Prerequisites

### 1. Enable Flakes (if not already enabled)

Edit `/etc/nixos/configuration.nix`:

```nix
{ config, pkgs, ... }:
{
  nix.settings.experimental-features = [ "nix-command" "flakes" ];
  
  # Optional: Enable direnv for automatic environment loading
  programs.direnv.enable = true;
  programs.direnv.nix-direnv.enable = true;
}
```

Then rebuild:
```bash
sudo nixos-rebuild switch
```

### 2. Enable direnv (Optional but Recommended)

```bash
direnv allow
```

This automatically loads the development environment when you `cd` into the project.

## Quick Start

### Option A: Using Flakes (Recommended)

```bash
cd /home/venom/redhat/edr-telemetry-engine

# Enter the dev shell
nix flake update
nix develop

# Verify .NET is installed
dotnet --version
```

### Option B: Using direnv (Most Convenient)

```bash
cd /home/venom/redhat/edr-telemetry-engine
direnv allow

# Environment loads automatically; verify:
dotnet --version
```

### Option C: One-off Command

```bash
nix develop --command bash -c "dotnet build"
```

## Development Workflow

### Build the Solution
```bash
nix develop --command dotnet build
```

### Run Unit Tests
```bash
nix develop --command dotnet test
```

### Run the Console Application
```bash
nix develop --command dotnet run --project src/EDRTelemetry.ConsoleApp
```

### Debug with VS Code

1. Open VS Code inside the flake:
```bash
nix develop --command code .
```

2. Install C# Dev Kit extension
3. Use `.vscode/launch.json` for debugging

## File Structure

```
edr-telemetry-engine/
├── flake.nix                    # NixOS development environment
├── .envrc                       # direnv configuration
├── src/
│   ├── EDRTelemetry.Core/       # Core models, interfaces, logic
│   ├── EDRTelemetry.Windows/    # Windows-specific ETW/Event Log parsers
│   ├── EDRTelemetry.Detectors/  # Detection rules & correlation engine
│   └── EDRTelemetry.ConsoleApp/ # CLI entry point
├── tests/
│   └── EDRTelemetry.Tests/      # Unit tests
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DETECTION_RULES.md
│   └── DEPLOYMENT.md
└── edr-telemetry-engine.sln     # Solution file
```

## Troubleshooting

### Issue: "nix-shell: command not found"

**Solution**: Update nixpkgs
```bash
nix flake update
```

### Issue: ".NET SDK version mismatch"

**Solution**: The flake pins `dotnet-sdk_8`. To use a different version, edit `flake.nix`:
```nix
dotnet-sdk_7  # Change to 7, 6, etc.
```

### Issue: "direnv not loading automatically"

**Solution**: Ensure it's enabled:
```bash
direnv allow
# Manually load if needed:
eval "$(direnv export bash)"
```

## Additional Resources

- [Nix Flakes Documentation](https://wiki.nixos.org/wiki/Flakes)
- [direnv Setup](https://direnv.net/)
- [.NET on NixOS](https://nixos.wiki/wiki/Dotnet)

## Next Steps

1. Enter the dev environment: `nix develop`
2. Build the solution: `dotnet build`
3. Run tests: `dotnet test`
4. Explore the codebase in `src/`
