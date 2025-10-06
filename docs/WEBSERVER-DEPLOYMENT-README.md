# IR Web Server - Minimal Docker Deployment

Complete guide to deploy **only the web server** from your large IR project to an Ubuntu server using Docker.

## Summary

This deployment creates a **minimal Docker image** (~200-300MB) containing:
- Only 13 Python files needed by web_server.py
- Minimal Python dependencies (see requirements-web.txt)
- Static files, templates, and data files
- Your .env configuration

Then pushes to Docker Hub and pulls on Ubuntu server.

---

## Quick Start

### 1. Prepare .env File

```bash
# Copy sample and edit with your values
cp .env.webserver.sample data/transient/.env
nano data/transient/.env  # Fill in required values
```

**Required variables:**
- XSOAR API credentials (prod and dev)
- TEAM_NAME
- Webex bot tokens
- See `.env.webserver.sample` for full list

### 2. (Optional) Use Web-Friendly Config

If you don't want to provide ALL environment variables:

```bash
cp my_config_webserver.py my_config.py
```

This version uses `.get()` with defaults for optional variables.

### 3. Build and Push

```bash
# Edit Docker Hub username
nano build-and-push.sh  # Change DOCKER_USERNAME

# Login to Docker Hub
docker login

# Build and push
./build-and-push.sh
```

### 4. Deploy on Ubuntu

```bash
# On Ubuntu server
docker pull yourusername/ir_webserver:latest
docker run -d -p 80:80 --name ir_webserver --restart unless-stopped yourusername/ir_webserver:latest
```

**Done!** Access at `http://your-ubuntu-server`

---

## Files Created

| File | Purpose |
|------|---------|
| `Dockerfile` | Minimal build with only required files |
| `requirements-web.txt` | Minimal Python dependencies |
| `.env.webserver.sample` | Sample environment variables |
| `my_config_webserver.py` | Config with optional defaults |
| `build-and-push.sh` | Script to build and push |
| `docker-compose.ubuntu.yml` | For Ubuntu deployment |
| `.dockerignore` | Excludes unnecessary files |
| `DOCKER-DEPLOYMENT.md` | Detailed deployment guide |

---

## What Gets Deployed?

### Python Files (13 total)
```
my_config.py
services/xsoar.py
services/approved_testing_utils.py
services/azdo.py
services/bot_rooms.py
src/secops.py
src/components/apt_names_fetcher.py
src/components/oncall.py
src/components/ticket_cache.py
src/utils/logging_utils.py
src/utils/http_utils.py
data/data_maps.py
web/web_server.py
```

### Data Files
```
data/transient/.env
data/transient/secOps/ (staffing files)
data/secOps/cell_names_by_shift.json
data/transient/de/APTAKAcleaned.xlsx
web/static/ (all)
web/templates/ (all)
```

---

## Workflow Diagram

```
┌─────────────┐
│  Your Mac   │
└──────┬──────┘
       │ 1. ./build-and-push.sh
       ├─► Build minimal Docker image
       ├─► Push to Docker Hub
       │
┌──────▼────────────┐
│   Docker Hub      │
│  (yourusername/   │
│   ir_webserver)   │
└──────┬────────────┘
       │
       │ 2. docker pull
       │
┌──────▼──────┐
│ Ubuntu      │
│ Server      │
│  ┌────────┐ │
│  │ Docker │ │
│  │Container│◄── Access on port 80
│  └────────┘ │
└─────────────┘
```

---

## Troubleshooting

### Build fails with "KeyError: 'SOME_ENV_VAR'"

**Solution 1:** Use `my_config_webserver.py`
```bash
cp my_config_webserver.py my_config.py
```

**Solution 2:** Add missing variable to `.env`
```bash
echo "SOME_ENV_VAR=value" >> data/transient/.env
```

### Docker Hub push fails

```bash
# Make sure you're logged in
docker login

# Check username in build-and-push.sh matches your Docker Hub username
nano build-and-push.sh
```

### Port 80 already in use on Ubuntu

```bash
# Use different port
docker run -d -p 8080:80 --name ir_webserver yourusername/ir_webserver:latest
# Access at http://server:8080
```

### Web server starts but shows errors

```bash
# Check logs
docker logs -f ir_webserver

# Common issues:
# - Missing .env variables → Check DOCKER-DEPLOYMENT.md for required vars
# - Missing data files → Make sure data/ directories are in build context
```

---

## Next Steps

- **Full documentation:** See `DOCKER-DEPLOYMENT.md`
- **Update deployment:** Rebuild image and restart container
- **Add SSL/HTTPS:** Set up nginx reverse proxy
- **Monitor logs:** `docker logs -f ir_webserver`

---

## Support

If you encounter issues:
1. Check `DOCKER-DEPLOYMENT.md` for detailed instructions
2. Verify `.env` has all required variables (see `.env.webserver.sample`)
3. Check Docker logs: `docker logs ir_webserver`
