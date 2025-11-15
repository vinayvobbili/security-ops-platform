# Quick Guide: Managing Secrets with SCP

## TL;DR - Change API Key

```bash
# On Mac
cd /Users/user/PycharmProjects/IR

# 1. If .secrets.age exists on Ubuntu, copy it first
scp vinay@inr106:~/pub/IR/data/transient/.secrets.age data/transient/

# 2. Decrypt
age -d -i ~/.config/age/key.txt data/transient/.secrets.age > data/transient/.secrets

# 3. Edit secrets
nano data/transient/.secrets

# 4. Re-encrypt
bash misc_scripts/encrypt_secrets.sh

# 5. Delete plaintext
rm data/transient/.secrets

# 6. Copy to Ubuntu
bash misc_scripts/sync_secrets.sh

# Done! Restart app on Ubuntu.
```

## First Time: Copy Age Key to Mac

```bash
# On Ubuntu - display your key
cat ~/.config/age/key.txt

# Copy the output (AGE-SECRET-KEY-1...)

# On Mac - save it
mkdir -p ~/.config/age
nano ~/.config/age/key.txt  # paste key
chmod 600 ~/.config/age/key.txt

# Test decryption works
cd /Users/user/PycharmProjects/IR
scp vinay@inr106:~/pub/IR/data/transient/.secrets.age data/transient/
age -d -i ~/.config/age/key.txt data/transient/.secrets.age
# Should show your secrets!
```

## Create New Secrets File

```bash
# On Mac
cd /Users/user/PycharmProjects/IR/data/transient

# Create .secrets with your API keys
cat > .secrets << 'EOF'
# Webex Bot Tokens
WEBEX_BOT_ACCESS_TOKEN_POKEDEX=xoxb-your-token-here
WEBEX_BOT_ACCESS_TOKEN_HAL9000=xoxb-your-token-here
WEBEX_BOT_EMAIL_POKEDEX=pokedex@webex.bot
WEBEX_BOT_EMAIL_HAL9000=hal9000@webex.bot

# Webex Room IDs
WEBEX_ROOM_ID_VINAY_TEST_SPACE=Y2lzY29zcGFyazovL3VzL1...
WEBEX_ROOM_ID_SOC_SHIFT_UPDATES=Y2lzY29zcGFyazovL3VzL1...

# XSOAR API Keys
XSOAR_PROD_AUTH_KEY=your-key-here
XSOAR_PROD_AUTH_ID=your-id-here
XSOAR_DEV_AUTH_KEY=your-dev-key-here
XSOAR_DEV_AUTH_ID=your-dev-id-here

# Azure DevOps
AZDO_PERSONAL_ACCESS_TOKEN=your-pat-here

# CrowdStrike
CROWD_STRIKE_RO_CLIENT_ID=your-id
CROWD_STRIKE_RO_CLIENT_SECRET=your-secret
CROWD_STRIKE_HOST_WRITE_CLIENT_ID=your-id
CROWD_STRIKE_HOST_WRITE_CLIENT_SECRET=your-secret
CROWD_STRIKE_RTR_CLIENT_ID=your-id
CROWD_STRIKE_RTR_CLIENT_SECRET=your-secret

# Other Services
CISCO_AMP_CLIENT_ID=your-id
CISCO_AMP_CLIENT_SECRET=your-secret
SNOW_CLIENT_KEY=your-key
SNOW_CLIENT_SECRET=your-secret
SNOW_FUNCTIONAL_ACCOUNT_ID=your-id
SNOW_FUNCTIONAL_ACCOUNT_PASSWORD=your-password
PHISH_FORT_API_KEY=your-key
TWILIO_ACCOUNT_SID=your-sid
TWILIO_AUTH_TOKEN=your-token
VONAGE_API_KEY=your-key
VONAGE_API_SECRET=your-secret
TANIUM_CLOUD_API_TOKEN=your-token
TANIUM_ONPREM_API_TOKEN=your-token
ZSCALER_USERNAME=your-username
ZSCALER_PASSWORD=your-password
ZSCALER_API_KEY=your-key
INFOBLOX_USERNAME=your-username
INFOBLOX_PASSWORD=your-password
PALO_ALTO_API_KEY=your-key
OPEN_WEATHER_MAP_API_KEY=your-key

# Lists and File Names
XSOAR_LISTS_FILENAME=lists.json
BARNACLES_APPROVED_USERS=user1,user2,user3
EOF

# Encrypt it
cd ../..
bash misc_scripts/encrypt_secrets.sh

# Copy to Ubuntu
bash misc_scripts/sync_secrets.sh

# Delete plaintext
rm data/transient/.secrets
```

## Workflow Comparison

### Change Non-Sensitive Config (.env)

```bash
# Mac
nano data/transient/.env
git add data/transient/.env
git commit -m "Change config"
git push

# Ubuntu
git pull
python web/web_server.py
```

**Simple!** Git handles everything.

### Change Secrets (.secrets → .secrets.age)

```bash
# Mac
scp vinay@inr106:~/pub/IR/data/transient/.secrets.age data/transient/
age -d -i ~/.config/age/key.txt data/transient/.secrets.age > data/transient/.secrets
nano data/transient/.secrets
bash misc_scripts/encrypt_secrets.sh
rm data/transient/.secrets
bash misc_scripts/sync_secrets.sh

# Ubuntu
python web/web_server.py  # restart
```

**Secure!** Secrets never touch git.

## Files Overview

```
Mac:
├── data/transient/
│   ├── .env              ← Edit, commit to git ✅
│   ├── .secrets          ← Edit, encrypt, delete ❌ (temp only)
│   └── .secrets.age      ← Encrypted, SCP to Ubuntu ⚠️ (never commit)
└── ~/.config/age/
    └── key.txt           ← Copy from Ubuntu once

Ubuntu:
├── data/transient/
│   ├── .env              ← Pull from git ✅
│   └── .secrets.age      ← Receive via SCP ⚠️
└── ~/.config/age/
    └── key.txt           ← Master key (never share)

Git Repo:
└── data/transient/
    └── .env              ← Only config file in git ✅
```

## Security Benefits

✅ **Secrets never in git** - Even encrypted ones
✅ **No git history pollution** - Can't search old commits for secrets
✅ **Future-proof** - If encryption breaks in 10 years, git history is clean
✅ **Simpler .gitignore** - Just block everything except .env
✅ **Direct transfer** - SCP is faster than git push/pull for binary files

## Helper Scripts

```bash
# Encrypt secrets
bash misc_scripts/encrypt_secrets.sh

# Sync to Ubuntu
bash misc_scripts/sync_secrets.sh

# Or do both
bash misc_scripts/encrypt_secrets.sh && bash misc_scripts/sync_secrets.sh
```

## Troubleshooting

**"Permission denied (publickey)"**
```bash
# Test SSH first
ssh vinay@inr106

# If that works, SCP should too
```

**"age: error: no identity matched any of the recipients"**
```bash
# Key mismatch - re-copy your age key from Ubuntu
scp vinay@inr106:~/.config/age/key.txt ~/.config/age/
chmod 600 ~/.config/age/key.txt
```

**"No .secrets.age on Ubuntu yet"**
```bash
# First time - create .secrets on Mac, encrypt, send
cd /Users/user/PycharmProjects/IR/data/transient
nano .secrets  # add your secrets
cd ../..
bash misc_scripts/encrypt_secrets.sh
bash misc_scripts/sync_secrets.sh
rm data/transient/.secrets
```
