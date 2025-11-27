# HTTPS Conversion Plan for metcirt-lab

## Current State

- **Port 80**: Waitress serving Flask app
- **Port 8080**: Proxy server (future use)
- **No SSL/TLS**: All traffic is HTTP

## Target State

- **Port 443**: nginx with SSL/TLS (HTTPS)
- **Port 80**: nginx redirect to HTTPS
- **Port 8080**: Waitress serving Flask app (internal only)
- **Port 8081**: Proxy server

## Architecture

```
External User
    ↓
nginx:443 (HTTPS) → Waitress:8080 (HTTP) → Flask App
    ↑
nginx:80 (HTTP redirect)
```

## Implementation Steps

### 1. Install nginx

```bash
ssh lab-vm "sudo apt update && sudo apt install -y nginx"
```

### 2. Obtain Certificate from Venafi

**Request certificate for:** `metcirt-lab-12.internal.company.com`

1. Submit certificate request through Venafi portal/API
2. Download certificate files:
    - `metcirt-lab.crt` (server certificate)
    - `metcirt-lab.key` (private key)
    - `chain.crt` (intermediate CA chain - if provided)

3. Copy certificates to server:

```bash
# Create SSL directory
ssh lab-vm "sudo mkdir -p /etc/nginx/ssl"

# Copy certificate files (run from your local machine)
scp metcirt-lab.crt metcirt-lab:/tmp/
scp metcirt-lab.key metcirt-lab:/tmp/
scp chain.crt metcirt-lab:/tmp/  # if applicable

# Move to proper location with correct permissions
ssh lab-vm "sudo mv /tmp/metcirt-lab.crt /etc/nginx/ssl/ && \
  sudo mv /tmp/metcirt-lab.key /etc/nginx/ssl/ && \
  sudo mv /tmp/chain.crt /etc/nginx/ssl/ && \
  sudo chmod 600 /etc/nginx/ssl/metcirt-lab.key && \
  sudo chmod 644 /etc/nginx/ssl/metcirt-lab.crt"
```

### 3. Update Configuration

**Update `.env` file:**
```
WEB_SERVER_PORT=8080
```

**Update `web_server.py` proxy port (line 66):**
```python
PROXY_PORT = 8081
```

### 4. Create nginx Configuration

File: `/etc/nginx/sites-available/metcirt-lab`

```nginx
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name metcirt-lab-12.internal.company.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    server_name metcirt-lab-12.internal.company.com;

    ssl_certificate /etc/nginx/ssl/metcirt-lab.crt;
    ssl_certificate_key /etc/nginx/ssl/metcirt-lab.key;
    ssl_trusted_certificate /etc/nginx/ssl/chain.crt;  # if chain provided

    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Proxy to Flask app
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (for streaming endpoints)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
    }
}
```

### 5. Enable Configuration

```bash
ssh lab-vm "sudo ln -s /etc/nginx/sites-available/metcirt-lab /etc/nginx/sites-enabled/ && \
  sudo rm -f /etc/nginx/sites-enabled/default"
```

### 6. Restart Services

```bash
# Stop current web server
ssh lab-vm "sudo pkill -f web_server.py"

# Start nginx
ssh lab-vm "sudo systemctl enable nginx && sudo systemctl restart nginx"

# Start web server on new port (5000)
ssh lab-vm "cd /home/vinay/pub/IR && \
  sudo nohup /home/vinay/pub/IR/.venv/bin/python web/web_server.py > /tmp/web_server.log 2>&1 &"
```

### 7. Verify

```bash
# Check nginx status
ssh lab-vm "sudo systemctl status nginx"

# Check ports
ssh lab-vm "sudo ss -tlnp | grep -E ':(80|443|8080|8081)'"

# Test HTTPS
curl https://metcirt-lab-12.internal.company.com
```

## Port Summary

| Port | Service  | Purpose                 | Access        |
|------|----------|-------------------------|---------------|
| 80   | nginx    | HTTP → HTTPS redirect   | External      |
| 443  | nginx    | HTTPS (SSL termination) | External      |
| 8080 | Waitress | Flask app               | Internal only |
| 8081 | Proxy    | Future use              | As needed     |

## Notes

- **Venafi certificate**: Trusted by all company browsers automatically
- **Certificate renewal**: Track expiration date and renew through Venafi before expiry
- **Firewall**: Ensure port 443 is open
- **Service management**: Consider creating systemd service for web_server.py auto-start

## Rollback Plan

If issues occur:

1. Stop nginx: `sudo systemctl stop nginx`
2. Change `.env` back to `WEB_SERVER_PORT=80`
3. Restart web server
