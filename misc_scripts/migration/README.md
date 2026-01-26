# Migration Files

Configuration templates for setting up a new Mac.

## Files

| Template | Destination | Notes |
|----------|-------------|-------|
| `ssh_config.template` | `~/.ssh/config` | SSH host aliases |
| `zshrc.template` | `~/.zshrc` | Shell configuration |
| `gitconfig.template` | `~/.gitconfig` | Git settings |

## Private Keys (NOT in repo)

These files must be manually copied from your old Mac:

```
~/.ssh/id_ed25519        -> ~/.ssh/id_ed25519
~/.ssh/id_ed25519.pub    -> ~/.ssh/id_ed25519.pub
~/.config/age/key.txt    -> ~/.config/age/key.txt
```

## Quick Setup

```bash
# 1. Copy private keys from backup (USB/secure storage)
mkdir -p ~/.ssh ~/.config/age
cp /path/to/backup/id_ed25519* ~/.ssh/
cp /path/to/backup/key.txt ~/.config/age/
chmod 600 ~/.ssh/id_ed25519 ~/.config/age/key.txt
chmod 644 ~/.ssh/id_ed25519.pub

# 2. Copy config templates
cp misc_scripts/migration/ssh_config.template ~/.ssh/config
cp misc_scripts/migration/zshrc.template ~/.zshrc
cp misc_scripts/migration/gitconfig.template ~/.gitconfig

# 3. Run setup script
bash misc_scripts/mac_migration_setup.sh
```

See [docs/MAC_MIGRATION.MD](../../docs/MAC_MIGRATION.MD) for full instructions.
