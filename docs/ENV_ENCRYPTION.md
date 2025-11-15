# Environment Variable Encryption Guide

This project uses `age` encryption to protect sensitive environment variables from unauthorized access, including users with sudo privileges.

## Overview

- **Plaintext .env files** can be read by any user with sudo access
- **Encrypted .env.age files** keep secrets secure even if someone has root access
- Secrets are **decrypted into memory only** at runtime, never written to disk in plaintext

## Initial Setup (One-time)

### 1. Install age and Generate Keys

On your Ubuntu server, run:

```bash
bash misc_scripts/setup_age_encryption.sh
```

This script will:
- Install `age` encryption tool (if not already installed)
- Generate an encryption key at `~/.config/age/key.txt`
- Set proper permissions (`600`) on the key file

**IMPORTANT**: Back up your private key (`~/.config/age/key.txt`) securely! If you lose it, you cannot decrypt your secrets.

### 2. Encrypt Your .env File

```bash
python misc_scripts/encrypt_secrets.py
```

This will:
- Read `data/transient/.env`
- Encrypt it to `data/transient/.env.age`
- Prompt you to delete the plaintext version

**Recommended**: Delete the plaintext .env file after verifying encryption works:
```bash
python misc_scripts/encrypt_secrets.py --delete-plaintext
```

### 3. Verify It Works

Test the decryption:
```bash
python src/utils/env_encryption.py
```

You should see:
```
✓ Loaded encrypted environment from .env.age
✓ Environment loaded successfully!
  Loaded XX variables
```

## Daily Usage

### Starting Your Application

Your application will automatically decrypt and load secrets at startup. No changes needed to how you run your bots:

```bash
python webex_bots/toodles.py
```

The application will:
1. Look for `data/transient/.env.age` (encrypted version)
2. Decrypt it into memory using `~/.config/age/key.txt`
3. Load variables into `os.environ`
4. Start normally

**Fallback**: If `.env.age` doesn't exist, it will look for plaintext `.env` and show a warning.

### Editing Secrets

Since the `.env` file is encrypted, you need to decrypt → edit → re-encrypt:

```bash
# 1. Decrypt to temporary plaintext
age -d -i ~/.config/age/key.txt data/transient/.env.age > data/transient/.env

# 2. Edit the file
nano data/transient/.env

# 3. Re-encrypt
python misc_scripts/encrypt_secrets.py --delete-plaintext

# 4. Restart your application
pkill -f toodles.py
python webex_bots/toodles.py
```

### Adding New Secrets

Same process as editing:
1. Decrypt the file
2. Add your new environment variable
3. Re-encrypt
4. Restart the application

## Security Features

✅ **Protection against sudo users**: Encrypted file cannot be read even with root access
✅ **Memory-only decryption**: Plaintext secrets never touch disk during runtime
✅ **Automatic fallback**: Works with plaintext .env during transition
✅ **No code changes**: Existing code continues to use `os.environ` normally
✅ **Audit logging**: Track all access attempts to the encryption key

## Audit Logging (Recommended)

While encryption protects your secrets, you should also monitor access to the encryption key itself. This helps detect if someone with sudo privileges is trying to access your key.

### Setup Audit Logging

```bash
# One-time setup
bash misc_scripts/setup_key_audit.sh
```

This installs and configures `auditd` to log all access to `~/.config/age/key.txt`, tracking:
- **Read** attempts
- **Write** attempts
- **Attribute changes**
- Who accessed it (user, command, timestamp)

### Check Audit Logs

View all key access events:
```bash
python misc_scripts/check_key_access.py
```

View only today's events:
```bash
python misc_scripts/check_key_access.py --today
```

View suspicious activity only:
```bash
python misc_scripts/check_key_access.py --suspicious
```

View summary statistics:
```bash
python misc_scripts/check_key_access.py --summary
```

### What's Considered Suspicious?

The audit script flags these patterns as suspicious:
- ✋ **Root access** to the key file
- ✋ **Direct cat/cp/scp** of the key
- ✋ **Network tools** (curl, wget, nc) accessing the key
- ✋ **Unexpected commands** touching the key file

**Note**: Your legitimate application access (via Python/age) is not flagged as suspicious.

### Automated Monitoring

Set up automated monitoring with alerts to Webex:

```bash
# Run manually to test
python misc_scripts/monitor_key_access.py --alert-webex --dry-run

# Set up cron job (check every hour)
crontab -e

# Add this line:
0 * * * * cd /home/vinay/pub/IR && .venv/bin/python misc_scripts/monitor_key_access.py --alert-webex
```

You'll receive a Webex message if suspicious activity is detected.

### Example Audit Output

```
✓ Event #1
  Time:     2025-01-10 14:32:15
  User:     vinay
  Command:  python
  Exe:      /home/vinay/pub/IR/.venv/bin/python

🚨 SUSPICIOUS Event #2
  Time:     2025-01-10 15:45:22
  User:     root
  Command:  cat
  Exe:      /usr/bin/cat
  Flags:    root_access, direct_cat_of_key
```

### Understanding the Limitations

**Important**: Audit logging is a **detective control**, not a **preventive control**.

- ✅ You'll know if someone accessed the key
- ✅ You can investigate and respond
- ❌ It doesn't prevent the access from happening

For true prevention against sudo users, you need hardware-based encryption (TPM) or external secret management (HashiCorp Vault).

## Files Created

```
scripts/
  setup_age_encryption.sh       # One-time setup script
  encrypt_env.py                 # Encryption utility
  setup_key_audit.sh             # Setup audit logging
  check_key_access.py            # Check audit logs
  monitor_key_access.py          # Automated monitoring with alerts

src/utils/
  env_encryption.py              # Core encryption/decryption module

data/transient/
  .env.age                       # Encrypted environment file (keep this)
  .env                           # Plaintext (delete after encrypting)
  key_access_state.json          # Monitoring state (auto-generated)

~/.config/age/
  key.txt                        # Your private key (backup securely!)

/etc/audit/rules.d/
  age-key.rules                  # Persistent audit rules (auto-generated)
```

## Troubleshooting

### Error: "age command not found"
```bash
# On Ubuntu
sudo apt install age

# On macOS
brew install age
```

### Error: "Age key not found"
Run the setup script again:
```bash
bash misc_scripts/setup_age_encryption.sh
```

### Error: "Encrypted env file not found"
You haven't encrypted your .env yet:
```bash
python misc_scripts/encrypt_secrets.py
```

### Application can't load secrets
1. Check that `.env.age` exists: `ls -l data/transient/.env.age`
2. Check that key exists: `ls -l ~/.config/age/key.txt`
3. Test decryption manually: `python src/utils/env_encryption.py`

### Audit logging not working
```bash
# Check if auditd is running
sudo systemctl status auditd

# Check if rule is active
sudo auditctl -l | grep age_key_access

# Re-run setup if needed
bash misc_scripts/setup_key_audit.sh
```

### No audit events showing up
```bash
# Test by accessing the key
cat ~/.config/age/key.txt

# Then check logs
python misc_scripts/check_key_access.py --last 5m
```

## Key Management

### Backing Up Your Key

```bash
# Copy to secure location (USB drive, password manager, etc.)
cp ~/.config/age/key.txt /secure/backup/location/age-key-backup.txt
```

### Using a Different Key Location

If you want to store the key elsewhere:

```python
# In my_config.py
load_encrypted_env(
    encrypted_path='data/transient/.env.age',
    key_path='/custom/path/to/key.txt'
)
```

### Rotating Keys

If you need to change your encryption key:

```bash
# 1. Decrypt with old key
age -d -i ~/.config/age/key.txt data/transient/.env.age > data/transient/.env

# 2. Generate new key
age-keygen -o ~/.config/age/key-new.txt

# 3. Encrypt with new key
python misc_scripts/encrypt_secrets.py --key ~/.config/age/key-new.txt

# 4. Replace old key
mv ~/.config/age/key-new.txt ~/.config/age/key.txt
```

## Advanced: Automating Decryption

For systemd services, you can decrypt secrets at service start:

```ini
# /etc/systemd/system/toodles.service
[Service]
Type=simple
User=vinay
WorkingDirectory=/home/vinay/pub/IR
ExecStart=/home/vinay/pub/IR/.venv/bin/python webex_bots/toodles.py
Restart=always

[Install]
WantedBy=multi-user.target
```

The Python application handles decryption automatically when it starts.

## Migration Path

If you're transitioning from plaintext to encrypted:

1. ✅ Setup is complete (you've done this)
2. ✅ Code updated to support encrypted files
3. 🔄 **Current state**: Both `.env` and `.env.age` may exist
4. ⏭️ **Next step**: Test with `.env.age`, then delete `.env`
5. ✅ **Final state**: Only `.env.age` exists, fully secure

## Additional Resources

- [age encryption tool](https://github.com/FiloSottile/age)
- [age specification](https://age-encryption.org/)
