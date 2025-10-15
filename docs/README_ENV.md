# Environment Configuration

This project uses a **dual-file** system for security and convenience:

## File Structure

| File | Purpose | Encrypted? | Committed? | Edit Directly? |
|------|---------|------------|------------|----------------|
| `.env` | Non-sensitive config | ❌ No | ✅ Yes | ✅ Yes - just edit! |
| `.secrets` | Plaintext secrets (temp) | ❌ No | ❌ No (gitignored) | ✅ Yes - then encrypt |
| `.secrets.age` | Encrypted secrets | ✅ Yes | ✅ Yes | ❌ No - decrypt first |

## Quick Start

### Change Non-Sensitive Config (Model Name, URLs, etc.)

**Just edit `.env` and restart - done!**

```bash
cd data/transient
nano .env

# Change this:
OLLAMA_LLM_MODEL=llama3:latest

# To this:
OLLAMA_LLM_MODEL=llama3.2:latest

# Save, restart app - no encryption needed!
```

### Change Secrets (API Keys, Passwords, etc.)

```bash
cd data/transient

# 1. Decrypt to .secrets (plaintext temp file)
age -d -i ~/.config/age/key.txt .secrets.age > .secrets

# 2. Edit the plaintext file
nano .secrets

# 3. Re-encrypt
cd ../..  # back to project root
bash scripts/encrypt_secrets.sh

# 4. Delete plaintext
rm data/transient/.secrets

# 5. Commit encrypted file
git add data/transient/.secrets.age
git commit -m "Update API keys"
```

## First Time Setup

### If You Have Existing `.env.age`

Migrate to the new structure:

```bash
cd ~/pub/IR

# 1. Decrypt old .env.age
age -d -i ~/.config/age/key.txt data/transient/.env.age > data/transient/.env.tmp

# 2. Split into .env (config) and .secrets (secrets)
# Edit .env.tmp and move non-sensitive vars to .env
# Move secrets to .secrets

# 3. Encrypt secrets
bash scripts/encrypt_secrets.sh

# 4. Clean up
rm data/transient/.env.tmp
rm data/transient/.env.age.backup
```

### Creating From Scratch

```bash
cd data/transient

# 1. Create .env with non-sensitive config
cat > .env << 'EOF'
# Ollama Configuration
OLLAMA_LLM_MODEL=llama3.2:latest
OLLAMA_EMBEDDING_MODEL=all-minilm:l6-v2

# Team
TEAM_NAME=DnR
EOF

# 2. Create .secrets with API keys/passwords
cat > .secrets << 'EOF'
# API Keys and Secrets
WEBEX_BOT_ACCESS_TOKEN_POKEDEX=your-token-here
XSOAR_PROD_AUTH_KEY=your-key-here
# ... add all secrets
EOF

# 3. Encrypt secrets
cd ../..
bash scripts/encrypt_secrets.sh

# 4. Delete plaintext secrets
rm data/transient/.secrets

# 5. Test loading
python -c "from my_config import get_config; print(get_config().ollama_llm_model)"
```

## What Goes Where?

### ✅ Put in `.env` (plaintext, safe to commit)

- Model names (`OLLAMA_LLM_MODEL`)
- Embedding models
- Server URLs (base URLs without auth)
- Timeout values
- Team names
- File paths
- Feature flags
- Timezone settings

**Rule of thumb:** If you're comfortable posting it on Slack, it goes in `.env`

### 🔐 Put in `.secrets` → `.secrets.age` (encrypted)

- API keys (anything with `KEY` in the name)
- Passwords (anything with `PASSWORD`)
- Tokens (anything with `TOKEN`)
- Auth credentials (anything with `AUTH`)
- Client secrets
- Personal access tokens

**Rule of thumb:** If leaking it would be a security incident, it goes in `.secrets`

## Benefits Over Single Encrypted File

| Task | Old Way (.env.age only) | New Way (.env + .secrets.age) |
|------|-------------------------|-------------------------------|
| Change model name | Decrypt, edit, re-encrypt | Just edit .env |
| View current config | Need decryption key | Just `cat .env` |
| Change API key | Decrypt, edit, re-encrypt | Decrypt, edit, re-encrypt |
| Share config with team | Can't (secrets inside) | Share .env (no secrets) |

## Testing

```bash
# Test configuration loads correctly
cd ~/pub/IR
python -c "from my_config import get_config; print(f'LLM: {get_config().ollama_llm_model}')"

# Expected output:
# ✓ Loaded plaintext config from .env
# ✓ Loaded encrypted secrets from .secrets.age
# LLM: llama3.2:latest
```

## Security Notes

- ✅ `.env` is safe to commit (no secrets)
- ✅ `.secrets.age` is safe to commit (encrypted)
- ❌ **Never commit** `.secrets` (gitignored, contains plaintext secrets)
- ✅ `.secrets` is in `.gitignore` for safety
- ✅ Delete `.secrets` after encrypting

## Quick Reference Commands

```bash
# Edit non-sensitive config (instant)
nano data/transient/.env

# View current plaintext config
cat data/transient/.env

# Edit secrets (decrypt → edit → re-encrypt)
age -d -i ~/.config/age/key.txt data/transient/.secrets.age > data/transient/.secrets
nano data/transient/.secrets
bash scripts/encrypt_secrets.sh
rm data/transient/.secrets

# Test config loads
python -c "from my_config import get_config; print(get_config().ollama_llm_model)"
```

## Troubleshooting

### "No .secrets.age found"
This is OK if you only use non-sensitive config. The app will run with just `.env`.

### "Age key not found"
Run: `bash scripts/setup_age_encryption.sh`

### "Accidentally committed .secrets"
```bash
# Remove from git
git rm --cached data/transient/.secrets
git commit -m "Remove plaintext secrets"

# Rotate all secrets (they've been exposed!)
# Then re-encrypt with new values
```
