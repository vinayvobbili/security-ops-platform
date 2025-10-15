# Quick Start: Environment Configuration

## TL;DR - Change Model Name (From Your Mac)

```bash
# On Mac
cd /Users/user/PycharmProjects/IR
nano data/transient/.env

# Add this line:
OLLAMA_LLM_MODEL=llama3.2:latest

# Commit and push
git add data/transient/.env
git commit -m "Switch to llama3.2"
git push

# On Ubuntu - pull and restart
git pull
python web/web_server.py
```

## New System Overview

| What You Want | What You Do |
|---------------|-------------|
| Change model name | Edit `.env` → git push |
| Change timeout value | Edit `.env` → git push |
| View current config | `cat .env` |
| Change API key | Edit `.secrets` → encrypt → SCP to Ubuntu |

## Security Model

- ✅ `.env` - Committed to git (no secrets)
- ❌ `.secrets` - Never committed (gitignored)
- ❌ `.secrets.age` - Never committed (gitignored, transferred via SCP)

**Why not commit .secrets.age?** Even though it's encrypted, keeping secrets completely out of git is best practice.

## First Time Setup (Ubuntu Server)

```bash
cd ~/pub/IR/data/transient

# 1. Create .env with your config
cat > .env << 'EOF'
# Ollama Configuration
OLLAMA_LLM_MODEL=llama3.2:latest
OLLAMA_EMBEDDING_MODEL=all-minilm:l6-v2

# Team
TEAM_NAME=DnR
EOF

# 2. If you have an old .env.age, decrypt it and split:
age -d -i ~/.config/age/key.txt .env.age > .env.tmp

# Edit .env.tmp:
# - Move non-sensitive config to .env
# - Move secrets to .secrets

nano .env.tmp  # copy non-sensitive vars to .env
nano .secrets  # copy secrets here

# 3. Encrypt secrets
cd ~/pub/IR
bash scripts/encrypt_secrets.sh

# 4. Clean up
rm data/transient/.env.tmp
rm data/transient/.secrets  # plaintext secrets deleted!
rm data/transient/.env.age   # old format no longer needed

# 5. Test
python -c "from my_config import get_config; print(get_config().ollama_llm_model)"
```

## Expected Output

```
✓ Loaded plaintext config from .env
✓ Loaded encrypted secrets from .secrets.age
llama3.2:latest
```

## File Summary

```
data/transient/
├── .env               ← Edit directly (committed to git)
├── .secrets.age       ← Encrypted secrets (committed to git)
├── .env.template      ← Example for new setup
└── README_ENV.md      ← Full documentation
```

**Never commit:**
- `.secrets` (plaintext temp file - in .gitignore)
- `.env.age` (old format - deprecated)

## Benefits

**Before (`.env.age` only):**
```bash
# Want to change model name?
age -d -i ~/.config/age/key.txt .env.age > temp
nano temp  # find the line, edit
age -e -r $(age-keygen -y ~/.config/age/key.txt) temp > .env.age
rm temp
# Annoying! 😫
```

**Now (`.env` + `.secrets.age`):**
```bash
# Want to change model name?
nano data/transient/.env  # edit, save, done
# Easy! 🎉
```

## Complete Example: Change to llama3.2:latest

```bash
# Ubuntu server
cd ~/pub/IR/data/transient

# Option 1: If .env already exists
nano .env
# Change OLLAMA_LLM_MODEL=llama3:latest
# To:     OLLAMA_LLM_MODEL=llama3.2:latest
# Save and exit

# Option 2: If .env doesn't exist yet
echo "OLLAMA_LLM_MODEL=llama3.2:latest" > .env
echo "OLLAMA_EMBEDDING_MODEL=all-minilm:l6-v2" >> .env
echo "TEAM_NAME=DnR" >> .env

# Test it works
cd ~/pub/IR
python -c "from my_config import get_config; print(f'LLM: {get_config().ollama_llm_model}')"

# Should output: LLM: llama3.2:latest

# Restart web server
python web/web_server.py
```

That's it! No encryption, no decryption, just edit and go.

## Questions?

- Full docs: `data/transient/README_ENV.md`
- Encryption script: `scripts/encrypt_secrets.sh`
- Issues: Check `.gitignore` includes `.secrets` and allows `.env`
