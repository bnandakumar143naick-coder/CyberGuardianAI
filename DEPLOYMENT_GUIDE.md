# CyberGuardian AI — Deployment Guide

## Production Deployment

This guide covers deploying CyberGuardian AI to production environments.

---

## Pre-Deployment Checklist

### 1. Security Configuration

- [ ] Set `FLASK_ENV=production` in environment
- [ ] Set `FLASK_DEBUG=False` for production
- [ ] Generate strong `SECRET_KEY`:
  ```python
  import secrets
  print(secrets.token_urlsafe(32))
  ```
- [ ] Set strong database password if using remote DB
- [ ] Review and enable security headers
- [ ] Configure CORS for trusted domains only
- [ ] Set up SSL/TLS certificate

### 2. Database

- [ ] Back up existing SQLite database
- [ ] Consider migrating to PostgreSQL for production
- [ ] Set up automated backups
- [ ] Test backup restoration process
- [ ] Configure connection pooling

### 3. File Uploads

- [ ] Create dedicated `/uploads` directory
- [ ] Set proper file permissions (755)
- [ ] Configure file size limits
- [ ] Set up automated cleanup for old uploads
- [ ] Test upload functionality

### 4. Dependencies

- [ ] Install all requirements: `pip install -r requirements.txt`
- [ ] Ensure Tesseract OCR is installed
- [ ] Verify Python version (3.8+)
- [ ] Test all analysis features work

### 5. Testing

- [ ] Run full test suite
- [ ] Test all 9 pages load
- [ ] Test all API endpoints
- [ ] Test file uploads
- [ ] Verify responsive design
- [ ] Check console for errors
- [ ] Test in multiple browsers
- [ ] Load test with multiple concurrent users

### 6. Monitoring

- [ ] Set up error logging
- [ ] Configure application monitoring
- [ ] Set up uptime monitoring
- [ ] Configure alerting
- [ ] Plan incident response

---

## Deployment Options

### Option 1: Traditional Server (Ubuntu/Debian)

#### Step 1: Provision Server
```bash
# Connect to server
ssh root@your.server.com

# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip python3-venv
sudo apt install -y tesseract-ocr
sudo apt install -y git
```

#### Step 2: Clone Project
```bash
cd /var/www
sudo git clone https://github.com/your-repo/cyberguardian.git
cd cyberguardian
```

#### Step 3: Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Step 4: Configure Application
```bash
# Create .env file
sudo nano .env
```

Add:
```
FLASK_ENV=production
FLASK_DEBUG=False
SECRET_KEY=your-generated-secret-key
DATABASE_PATH=/var/www/cyberguardian/database/cyberguardian.db
UPLOAD_FOLDER=/var/www/cyberguardian/uploads
```

#### Step 5: Set Up Gunicorn
```bash
# Install Gunicorn
pip install gunicorn

# Test Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Create systemd service
sudo nano /etc/systemd/system/cyberguardian.service
```

Add:
```ini
[Unit]
Description=CyberGuardian AI
After=network.target

[Service]
User=www-data
WorkingDirectory=/var/www/cyberguardian
Environment="PATH=/var/www/cyberguardian/venv/bin"
ExecStart=/var/www/cyberguardian/venv/bin/gunicorn \
  -w 4 \
  -b 0.0.0.0:5000 \
  app:app

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

#### Step 6: Enable Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable cyberguardian
sudo systemctl start cyberguardian
sudo systemctl status cyberguardian
```

#### Step 7: Configure Nginx
```bash
sudo apt install -y nginx

# Create Nginx config
sudo nano /etc/nginx/sites-available/cyberguardian
```

Add:
```nginx
upstream cyberguardian_app {
    server 127.0.0.1:5000;
}

server {
    listen 80;
    server_name your.domain.com;

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your.domain.com;

    ssl_certificate /etc/letsencrypt/live/your.domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your.domain.com/privkey.pem;

    client_max_body_size 8M;

    location / {
        proxy_pass http://cyberguardian_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias /var/www/cyberguardian/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' https: data: 'unsafe-inline';" always;
}
```

#### Step 8: Enable Nginx Site
```bash
sudo ln -s /etc/nginx/sites-available/cyberguardian \
  /etc/nginx/sites-enabled/

sudo nginx -t
sudo systemctl restart nginx
```

#### Step 9: Set Up SSL with Let's Encrypt
```bash
sudo apt install -y certbot python3-certbot-nginx

sudo certbot certonly --standalone -d your.domain.com

# Auto-renewal
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer
```

---

### Option 2: Docker

#### Create Dockerfile
```dockerfile
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libsm6 \
    libxext6 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create directories
RUN mkdir -p database uploads

# Expose port
EXPOSE 5000

# Run application
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

#### Create docker-compose.yml
```yaml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "5000:5000"
    environment:
      FLASK_ENV: production
      FLASK_DEBUG: "False"
      SECRET_KEY: ${SECRET_KEY}
    volumes:
      - ./database:/app/database
      - ./uploads:/app/uploads
    restart: always
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - web
    restart: always
```

#### Run with Docker
```bash
# Build image
docker build -t cyberguardian:latest .

# Run container
docker run -p 5000:5000 \
  -e FLASK_ENV=production \
  -e SECRET_KEY=your-secret-key \
  -v $(pwd)/database:/app/database \
  -v $(pwd)/uploads:/app/uploads \
  cyberguardian:latest

# Or use docker-compose
docker-compose up -d
```

---

### Option 3: Heroku

#### Prerequisites
```bash
# Install Heroku CLI
curl https://cli-assets.heroku.com/install.sh | sh

# Login
heroku login
```

#### Create Procfile
```
web: gunicorn -w 4 -b 0.0.0.0:$PORT app:app
```

#### Create runtime.txt
```
python-3.10.0
```

#### Deploy
```bash
# Create app
heroku create cyberguardian-app

# Set environment variables
heroku config:set FLASK_ENV=production
heroku config:set SECRET_KEY=your-secret-key

# Deploy
git push heroku main

# View logs
heroku logs --tail
```

---

### Option 4: AWS/DigitalOcean App Platform

#### AWS Elastic Beanstalk
```bash
# Install EB CLI
pip install awsebcli

# Initialize
eb init -p python-3.10 cyberguardian --region us-east-1

# Create environment
eb create cyberguardian-env

# Deploy
eb deploy

# Monitor
eb status
eb logs
```

#### DigitalOcean App Platform
1. Connect GitHub repository
2. Create App Specification (app.yaml):
```yaml
name: cyberguardian
services:
- name: web
  github:
    repo: your-username/cyberguardian
    branch: main
  build_command: pip install -r requirements.txt
  run_command: gunicorn -w 4 -b 0.0.0.0:5000 app:app
  http_port: 5000
  health_check:
    http_path: /api/health
  envs:
  - key: FLASK_ENV
    value: production
  - key: SECRET_KEY
    value: ${SECRET_KEY}
```
3. Deploy through DigitalOcean dashboard

---

## Post-Deployment Configuration

### Enable HTTPS/SSL

```bash
# Generate self-signed certificate (development)
openssl req -x509 -newkey rsa:4096 -nodes \
  -out cert.pem -keyout key.pem -days 365

# For production, use Let's Encrypt (see above)
```

### Configure Logging

```python
# In app.py, add logging configuration

import logging
from logging.handlers import RotatingFileHandler

if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    file_handler = RotatingFileHandler(
        'logs/cyberguardian.log',
        maxBytes=10240000,
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('CyberGuardian AI startup')
```

### Set Up Monitoring

```bash
# Using Sentry for error tracking
pip install sentry-sdk

# In app.py
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

sentry_sdk.init(
    dsn="your-sentry-dsn",
    integrations=[FlaskIntegration()],
    traces_sample_rate=1.0
)
```

### Automated Backups

```bash
# Create backup script (backup.sh)
#!/bin/bash
BACKUP_DIR="/var/backups/cyberguardian"
DB_PATH="/var/www/cyberguardian/database/cyberguardian.db"
DATE=$(date +%Y%m%d_%H%M%S)

cp $DB_PATH $BACKUP_DIR/cyberguardian_$DATE.db.backup
gzip $BACKUP_DIR/cyberguardian_$DATE.db.backup

# Keep only last 30 days
find $BACKUP_DIR -name "*.backup.gz" -mtime +30 -delete

# Add to crontab
# 0 2 * * * /path/to/backup.sh
```

---

## Performance Tuning

### Database Optimization

```python
# Add index to frequently queried columns
# In database.py init_db():

conn.execute("""
    CREATE INDEX IF NOT EXISTS idx_risk_level 
    ON scans(risk_level)
""")

conn.execute("""
    CREATE INDEX IF NOT EXISTS idx_timestamp 
    ON scans(timestamp DESC)
""")
```

### Gunicorn Configuration

```bash
# Production settings
gunicorn -w 8 \           # 4 x CPU cores
  --worker-class sync \    # Sync workers
  --worker-tmp-dir /dev/shm \  # Use RAM for temp
  --max-requests 1000 \    # Worker restart
  --timeout 60 \           # Request timeout
  -b 0.0.0.0:5000 \
  app:app
```

### Nginx Caching

```nginx
# Cache static assets
location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
    expires 30d;
    add_header Cache-Control "public, immutable";
}

# Compress responses
gzip on;
gzip_types text/plain text/css text/javascript 
  application/json application/javascript;
gzip_min_length 1000;
```

---

## Monitoring & Maintenance

### Key Metrics to Monitor

1. **Uptime** - Continuous availability
2. **Response Time** - Average request time
3. **Error Rate** - Failed requests percentage
4. **CPU Usage** - Server CPU load
5. **Memory Usage** - RAM consumption
6. **Disk Space** - Database and uploads
7. **Database Size** - Scan history growth

### Maintenance Tasks

```bash
# Weekly
- Review error logs
- Check disk space
- Verify backups exist

# Monthly
- Update dependencies: pip install --upgrade -r requirements.txt
- Rotate logs
- Review security headers
- Test backup restoration

# Quarterly
- Full security audit
- Performance analysis
- Dependency updates
- Database maintenance

# Annually
- SSL certificate renewal
- Security assessment
- Plan next major version
```

---

## Troubleshooting Production

### Application Won't Start

```bash
# Check logs
journalctl -u cyberguardian -n 100

# Check port availability
lsof -i :5000

# Verify permissions
ls -la /var/www/cyberguardian/

# Test with Flask directly
export FLASK_APP=app.py
export FLASK_ENV=production
python -m flask run
```

### High Memory Usage

```bash
# Check memory
free -h

# Monitor process
top -p $(pgrep -f gunicorn)

# Reduce worker count
# Increase worker restart frequency
# Check for memory leaks in logs
```

### Database Issues

```bash
# Check database integrity
sqlite3 database/cyberguardian.db "PRAGMA integrity_check;"

# Vacuum database (defragment)
sqlite3 database/cyberguardian.db "VACUUM;"

# Export and reimport if corrupted
sqlite3 database/cyberguardian.db ".dump" > backup.sql
```

---

## Rollback Procedure

```bash
# If new deployment causes issues:

# 1. Stop new version
systemctl stop cyberguardian

# 2. Restore previous code
git checkout previous-commit

# 3. Restore previous database (if needed)
cp database/cyberguardian.db.backup database/cyberguardian.db

# 4. Start service
systemctl start cyberguardian

# 5. Verify
curl http://localhost:5000/api/health
```

---

## Security Hardening

### Firewall Rules

```bash
# UFW (Ubuntu)
sudo ufw enable
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw deny 5000      # Block direct Flask
```

### File Permissions

```bash
cd /var/www/cyberguardian

# Secure directories
chmod 755 .
chmod 755 static
chmod 755 templates
chmod 700 database
chmod 700 uploads

# Secure files
chmod 644 app.py
chmod 600 .env
chmod 644 requirements.txt
```

### Regular Updates

```bash
# Create update script
#!/bin/bash

# Stop service
systemctl stop cyberguardian

# Pull latest code
git pull origin main

# Update dependencies
pip install --upgrade -r requirements.txt

# Run migrations (if any)
# python migrations.py

# Restart service
systemctl start cyberguardian

# Verify
systemctl status cyberguardian
```

---

## Conclusion

Successfully deployed CyberGuardian AI to production requires:
- Proper configuration and secrets management
- Database backups and recovery procedures
- Monitoring and alerting setup
- Regular maintenance and updates
- Security hardening and audit logs
- Rollback procedures for emergencies

For additional help, consult server documentation or contact your hosting provider.

---

**Last Updated:** September 17, 2026
