# Jenkins Installation Guide

Jenkins is a free and open-source automation server for building, testing, and deploying applications. Originally developed by Kohsuke Kawaguchi and now maintained by the Jenkins community, Jenkins is the industry-leading CI/CD platform with extensive plugin ecosystem and enterprise-grade features. It serves as a FOSS alternative to commercial CI/CD solutions like TeamCity, GitLab CI Premium, or Azure DevOps Server, offering unlimited build minutes, unlimited private repositories, and advanced pipeline capabilities without licensing costs, with features like distributed builds, Pipeline as Code, and extensive plugin ecosystem.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 2 cores minimum (4+ cores recommended for production)
  - RAM: 2GB minimum (8GB+ recommended for production)
  - Storage: 50GB minimum (SSD recommended for build performance)
  - Network: Stable connectivity for agent communication and external integrations
- **Operating System**: 
  - Linux: Any modern distribution with kernel 3.2+
  - macOS: 10.13+ (High Sierra or newer)
  - Windows: Windows Server 2016+ or Windows 10
  - FreeBSD: 11.0+
- **Network Requirements**:
  - Port 8080 (default Jenkins HTTP)
  - Port 50000 (default Jenkins agent communication)
  - Additional ports for external integrations (webhooks, etc.)
- **Dependencies**:
  - Java 11 or 17 LTS (OpenJDK recommended)
  - systemd or compatible init system (Linux)
  - Root or administrative access for installation
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Install Java 17 LTS
sudo dnf install -y java-17-openjdk java-17-openjdk-devel

# Add Jenkins repository
curl -fsSL https://pkg.jenkins.io/redhat-stable/jenkins.io-2023.key | sudo tee /etc/yum.repos.d/jenkins.io.key

sudo tee /etc/yum.repos.d/jenkins.repo <<EOF
[jenkins]
name=Jenkins-stable
baseurl=http://pkg.jenkins.io/redhat-stable
gpgcheck=1
gpgkey=file:///etc/yum.repos.d/jenkins.io.key
enabled=1
EOF

# Install Jenkins
sudo dnf install -y jenkins

# Enable and start service
sudo systemctl enable --now jenkins

# Configure firewall
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --permanent --add-port=50000/tcp
sudo firewall-cmd --reload

# Get initial admin password
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
```

### Debian/Ubuntu

```bash
# Update system packages
sudo apt update

# Install Java 17 LTS
sudo apt install -y openjdk-17-jdk openjdk-17-jre

# Add Jenkins repository
wget -O /tmp/jenkins-key.asc https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key
sudo mv /tmp/jenkins-key.asc /etc/apt/trusted.gpg.d/jenkins.asc

echo "deb https://pkg.jenkins.io/debian-stable binary/" | sudo tee /etc/apt/sources.list.d/jenkins.list

# Update package index
sudo apt update

# Install Jenkins
sudo apt install -y jenkins

# Enable and start service
sudo systemctl enable --now jenkins

# Configure firewall
sudo ufw allow 8080/tcp
sudo ufw allow 50000/tcp

# Get initial admin password
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
```

### Arch Linux

```bash
# Install Java 17 LTS
sudo pacman -S jdk17-openjdk

# Install Jenkins from AUR
yay -S jenkins

# Alternative: Install manually from AUR
git clone https://aur.archlinux.org/jenkins.git
cd jenkins
makepkg -si

# Create jenkins user if not created
sudo useradd -r -d /var/lib/jenkins -s /sbin/nologin jenkins

# Enable and start service
sudo systemctl enable --now jenkins

# Get initial admin password
sudo cat /var/lib/jenkins/secrets/initialAdminPassword

# Configuration location: /etc/jenkins/
```

### Alpine Linux

```bash
# Jenkins is not officially packaged for Alpine Linux
# Use Docker or manual installation

# Method 1: Docker installation
apk add --no-cache docker docker-compose
rc-update add docker default
rc-service docker start

# Create Jenkins data directory
mkdir -p /var/lib/jenkins

# Run Jenkins container
docker run -d \
  --name jenkins \
  --restart unless-stopped \
  -p 8080:8080 \
  -p 50000:50000 \
  -v /var/lib/jenkins:/var/jenkins_home \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --group-add $(getent group docker | cut -d: -f3) \
  jenkins/jenkins:lts-jdk17

# Get initial admin password
docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword

# Method 2: Manual installation with OpenJDK
apk add --no-cache openjdk17-jre-headless
wget https://get.jenkins.io/war-stable/latest/jenkins.war -O /opt/jenkins.war

# Create jenkins user and directories
adduser -D -s /sbin/nologin jenkins
mkdir -p /var/lib/jenkins /var/log/jenkins
chown -R jenkins:jenkins /var/lib/jenkins /var/log/jenkins

# Create init script
tee /etc/init.d/jenkins <<'EOF'
#!/sbin/openrc-run
name="Jenkins"
command="java"
command_args="-jar /opt/jenkins.war --httpPort=8080 --ajp13Port=-1"
command_user="jenkins"
pidfile="/run/jenkins.pid"
command_background="yes"
depend() {
    need net
}
EOF

chmod +x /etc/init.d/jenkins
rc-update add jenkins default
rc-service jenkins start
```

### openSUSE/SLES

```bash
# openSUSE Leap/Tumbleweed
sudo zypper install -y java-17-openjdk java-17-openjdk-devel

# Add Jenkins repository
sudo zypper addrepo -G https://pkg.jenkins.io/opensuse-stable/ jenkins
sudo zypper refresh

# Install Jenkins
sudo zypper install -y jenkins

# SLES 15
sudo SUSEConnect -p sle-module-development-tools/15.5/x86_64
sudo zypper install -y java-17-openjdk jenkins

# Enable and start service
sudo systemctl enable --now jenkins

# Configure firewall
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --permanent --add-port=50000/tcp
sudo firewall-cmd --reload

# Get initial admin password
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
```

### macOS

```bash
# Using Homebrew
brew install jenkins-lts

# Start Jenkins service
brew services start jenkins-lts

# Or run manually
jenkins-lts

# Alternative: Install specific version
brew install jenkins-lts@2.414

# Get initial admin password
cat ~/.jenkins/secrets/initialAdminPassword

# Configuration location: ~/.jenkins/
# Alternative: /usr/local/var/jenkins_home/ (Intel Macs)
# Alternative: /opt/homebrew/var/jenkins_home/ (Apple Silicon)
```

### FreeBSD

```bash
# Using pkg
pkg install jenkins openjdk17

# Using ports
cd /usr/ports/devel/jenkins
make install clean

# Enable Jenkins
echo 'jenkins_enable="YES"' >> /etc/rc.conf
echo 'jenkins_java_home="/usr/local/openjdk17"' >> /etc/rc.conf

# Create jenkins user and directories
pw useradd jenkins -d /usr/local/jenkins -s /sbin/nologin
mkdir -p /usr/local/jenkins
chown jenkins:jenkins /usr/local/jenkins

# Start service
service jenkins start

# Get initial admin password
cat /usr/local/jenkins/secrets/initialAdminPassword

# Configuration location: /usr/local/jenkins/
```

### Windows

```powershell
# Method 1: Using Chocolatey
choco install jenkins

# Method 2: Using Scoop
scoop install jenkins

# Method 3: Manual installation
# Download from https://www.jenkins.io/download/
# Run jenkins.msi installer

# Method 4: Windows service installation
# Download jenkins.war
# Install as Windows service
java -jar jenkins.war --httpPort=8080 --install

# Start service
net start Jenkins

# Get initial admin password
Get-Content "C:\Program Files\Jenkins\secrets\initialAdminPassword"

# Configuration location: C:\Program Files\Jenkins\
# Or: %JENKINS_HOME% (if custom location)
```

## Initial Configuration

### First-Run Setup

1. **Java Environment Setup**:
```bash
# Set JAVA_HOME (Linux/macOS)
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk
echo 'export JAVA_HOME=/usr/lib/jvm/java-17-openjdk' >> ~/.bashrc

# Verify Java installation
java -version
```

2. **Default configuration locations**:
- RHEL/CentOS/Rocky/AlmaLinux: `/var/lib/jenkins/`, `/etc/sysconfig/jenkins`
- Debian/Ubuntu: `/var/lib/jenkins/`, `/etc/default/jenkins`
- Arch Linux: `/var/lib/jenkins/`, `/etc/jenkins/`
- Alpine Linux: `/var/lib/jenkins/` (Docker) or `/var/lib/jenkins/` (manual)
- openSUSE/SLES: `/var/lib/jenkins/`, `/etc/sysconfig/jenkins`
- macOS: `~/.jenkins/` or `/usr/local/var/jenkins_home/`
- FreeBSD: `/usr/local/jenkins/`
- Windows: `C:\Program Files\Jenkins\` or `%JENKINS_HOME%`

3. **Essential initial configuration**:

```bash
# Initial web setup (after accessing http://your-server:8080)
# 1. Enter admin password from: /var/lib/jenkins/secrets/initialAdminPassword
# 2. Install suggested plugins or select specific plugins
# 3. Create first admin user
# 4. Configure Jenkins URL

# Essential plugins to install:
# - Pipeline plugins (Pipeline Suite)
# - Git plugin
# - Credentials Binding Plugin
# - Build Timeout Plugin
# - Timestamper Plugin
# - Workspace Cleanup Plugin
# - Blue Ocean (modern UI)
# - Matrix Authorization Strategy Plugin
```

### Testing Initial Setup

```bash
# Check service status
sudo systemctl status jenkins

# Check web interface
curl -I http://localhost:8080

# Test Java version
java -version

# Check Jenkins process
ps aux | grep jenkins

# Verify Jenkins CLI
wget http://localhost:8080/jnlpJars/jenkins-cli.jar
java -jar jenkins-cli.jar -s http://localhost:8080 version

# Check available plugins
java -jar jenkins-cli.jar -s http://localhost:8080 list-plugins
```

**WARNING:** Change the default admin password immediately and configure proper authentication!

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable Jenkins to start on boot
sudo systemctl enable jenkins

# Start Jenkins
sudo systemctl start jenkins

# Stop Jenkins
sudo systemctl stop jenkins

# Restart Jenkins
sudo systemctl restart jenkins

# Graceful restart (wait for running builds)
sudo systemctl reload jenkins

# Check status
sudo systemctl status jenkins

# View logs
sudo journalctl -u jenkins -f

# Edit service configuration
sudo systemctl edit jenkins
# Add custom environment variables or JVM options
```

### OpenRC (Alpine Linux)

```bash
# Docker-based installation
docker start jenkins
docker stop jenkins
docker restart jenkins

# Check container status
docker ps | grep jenkins

# View logs
docker logs -f jenkins

# Manual installation
rc-update add jenkins default
rc-service jenkins start
rc-service jenkins stop
rc-service jenkins restart
rc-service jenkins status
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'jenkins_enable="YES"' >> /etc/rc.conf

# Start Jenkins
service jenkins start

# Stop Jenkins
service jenkins stop

# Restart Jenkins
service jenkins restart

# Check status
service jenkins status

# View logs
tail -f /var/log/jenkins/jenkins.log
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start jenkins-lts
brew services stop jenkins-lts
brew services restart jenkins-lts

# Check status
brew services list | grep jenkins

# Manual control
jenkins-lts --httpPort=8080

# View logs
tail -f /usr/local/var/log/jenkins/jenkins.log
```

### Windows Service Manager

```powershell
# Start Jenkins service
net start Jenkins

# Stop Jenkins service
net stop Jenkins

# Using PowerShell
Start-Service Jenkins
Stop-Service Jenkins
Restart-Service Jenkins

# Check status
Get-Service Jenkins

# View logs (Windows Event Log)
Get-EventLog -LogName Application -Source Jenkins

# Or check Jenkins logs
Get-Content "C:\Program Files\Jenkins\logs\jenkins.log" -Tail 50 -Wait
```

## Advanced Configuration

### High Availability Configuration

```bash
# Multi-master setup with shared storage
# Method 1: Shared filesystem (NFS, GlusterFS)
sudo mkdir -p /shared/jenkins
sudo mount -t nfs nfs-server:/jenkins /shared/jenkins

# Update Jenkins home
sudo systemctl edit jenkins
# Add:
[Service]
Environment="JENKINS_HOME=/shared/jenkins"

# Method 2: Database-backed configuration
# Install CloudBees Jenkins Enterprise plugins for HA
# Configure external database (PostgreSQL recommended)

# Agent configuration for load distribution
sudo tee /var/lib/jenkins/casc_configs/agents.yaml <<EOF
jenkins:
  nodes:
    - permanent:
        name: "linux-agent-1"
        remoteFS: "/var/lib/jenkins"
        numExecutors: 4
        launcher:
          ssh:
            host: "agent1.example.com"
            credentialsId: "ssh-agent-key"
    - permanent:
        name: "windows-agent-1"
        remoteFS: "C:\\Jenkins"
        numExecutors: 2
        launcher:
          command:
            command: "java -jar agent.jar"
EOF
```

### Advanced Security Settings

```bash
# Configure Jenkins Configuration as Code (JCasC) for security
sudo tee /var/lib/jenkins/casc_configs/security.yaml <<EOF
jenkins:
  securityRealm:
    ldap:
      configurations:
        - server: "ldaps://ldap.example.com:636"
          rootDN: "DC=example,DC=com"
          userSearchBase: "OU=Users"
          userSearch: "(&(objectCategory=Person)(objectClass=user)(sAMAccountName={0}))"
          groupSearchBase: "OU=Groups"
          managerDN: "CN=jenkins,OU=Service Accounts,DC=example,DC=com"
          managerPasswordSecret: "ldap-password"
          
  authorizationStrategy:
    roleBased:
      roles:
        global:
          - name: "admin"
            permissions:
              - "Overall/Administer"
            assignments:
              - "jenkins-admins"
          - name: "developer"
            permissions:
              - "Overall/Read"
              - "Job/Build"
              - "Job/Read"
            assignments:
              - "developers"

security:
  globalJobDslSecurityConfiguration:
    useScriptSecurity: true
  scriptApproval:
    approvedSignatures:
      - "method java.lang.String trim"
      - "staticMethod java.lang.System getProperty java.lang.String"

unclassified:
  location:
    adminAddress: "jenkins@example.com"
    url: "https://jenkins.example.com/"
    
  mailer:
    smtpHost: "smtp.example.com"
    smtpPort: 587
    charset: "UTF-8"
    authentication:
      username: "jenkins@example.com"
      password: "{AQAAABAAAAAQhudQr8JjwNNI9pj8oI3L2gE=}"
    useSsl: false
    useTls: true
EOF
```

## Reverse Proxy Setup

### nginx Configuration

```nginx
# /etc/nginx/sites-available/jenkins
upstream jenkins {
    server 127.0.0.1:8080 fail_timeout=0;
    keepalive 32;
}

server {
    listen 80;
    server_name jenkins.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name jenkins.example.com;

    ssl_certificate /etc/letsencrypt/live/jenkins.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/jenkins.example.com/privkey.pem;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    client_max_body_size 100M;
    
    location / {
        proxy_pass http://jenkins;
        proxy_redirect default;
        proxy_http_version 1.1;
        
        # Required headers for Jenkins
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Port $server_port;
        
        # WebSocket support for Jenkins
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeout settings
        proxy_connect_timeout 90;
        proxy_send_timeout 90;
        proxy_read_timeout 90;
        
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_max_temp_file_size 0;
    }
}
```

### HAProxy Configuration

```haproxy
# /etc/haproxy/haproxy.cfg
frontend jenkins_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/jenkins.pem
    redirect scheme https if !{ ssl_fc }
    default_backend jenkins_servers

backend jenkins_servers
    mode http
    balance roundrobin
    option httpchk GET /login
    http-check expect status 200
    server jenkins1 127.0.0.1:8080 check inter 30s rise 2 fall 3
    server jenkins2 127.0.0.1:8081 check inter 30s rise 2 fall 3 backup

    # Headers for Jenkins
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Forwarded-Port %[dst_port]
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

### Apache HTTP Server Configuration

```apache
# /etc/apache2/sites-available/jenkins.conf
<VirtualHost *:80>
    ServerName jenkins.example.com
    Redirect permanent / https://jenkins.example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName jenkins.example.com
    
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/jenkins.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/jenkins.example.com/privkey.pem
    
    # Security headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection "1; mode=block"
    
    ProxyPreserveHost On
    ProxyRequests Off
    
    ProxyPass / http://127.0.0.1:8080/ nocanon
    ProxyPassReverse / http://127.0.0.1:8080/
    ProxyPassReverse  /  http://jenkins.example.com/
    
    # WebSocket support
    RewriteEngine on
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/?(.*) "ws://127.0.0.1:8080/$1" [P,L]
    
    AllowEncodedSlashes NoDecode
</VirtualHost>
```

## Security Configuration

### SSL/TLS Setup

```bash
# Generate self-signed certificate (development only)
sudo mkdir -p /etc/jenkins/ssl
sudo openssl req -x509 -newkey rsa:4096 -keyout /etc/jenkins/ssl/jenkins.key -out /etc/jenkins/ssl/jenkins.crt -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=jenkins.example.com"

# Create Java keystore
sudo keytool -genkey -alias jenkins -keyalg RSA -keystore /etc/jenkins/ssl/jenkins.jks -keysize 2048 -dname "CN=jenkins.example.com,OU=IT,O=Organization,L=City,ST=State,C=US" -storepass changeit -keypass changeit

# Configure Jenkins to use HTTPS
sudo systemctl edit jenkins
# Add:
[Service]
Environment="JENKINS_OPTS=--httpPort=-1 --httpsPort=8443 --httpsKeyStore=/etc/jenkins/ssl/jenkins.jks --httpsKeyStorePassword=changeit"

sudo systemctl restart jenkins

# Or use Let's Encrypt with reverse proxy (recommended)
sudo certbot --nginx -d jenkins.example.com
```

### Authentication and Authorization

```bash
# Configure LDAP authentication via JCasC
sudo tee /var/lib/jenkins/casc_configs/auth.yaml <<EOF
jenkins:
  securityRealm:
    ldap:
      configurations:
        - server: "ldaps://ldap.example.com:636"
          rootDN: "DC=example,DC=com"
          inhibitInferRootDN: false
          userSearchBase: "OU=Users"
          userSearch: "(&(objectCategory=Person)(objectClass=user)(sAMAccountName={0}))"
          groupSearchBase: "OU=Groups"
          groupSearchFilter: "(&(objectClass=group)(cn={0}))"
          managerDN: "CN=jenkins,OU=Service Accounts,DC=example,DC=com"
          managerPasswordSecret: "ldap-password"
          displayNameAttributeName: "displayName"
          mailAddressAttributeName: "mail"

  authorizationStrategy:
    roleBased:
      roles:
        global:
          - name: "jenkins-admins"
            permissions:
              - "Overall/Administer"
            assignments:
              - "Domain Admins"
              - "jenkins-admins"
          - name: "developers"
            permissions:
              - "Overall/Read"
              - "Job/Build"
              - "Job/Cancel"
              - "Job/Read"
              - "Job/Workspace"
              - "Run/Replay"
              - "Run/Update"
            assignments:
              - "developers"
              - "authenticated"
          - name: "viewers"
            permissions:
              - "Overall/Read"
              - "Job/Read"
            assignments:
              - "viewers"
              
credentials:
  system:
    domainCredentials:
      - credentials:
          - usernamePassword:
              scope: GLOBAL
              id: "ldap-password"
              username: "CN=jenkins,OU=Service Accounts,DC=example,DC=com"
              password: "{AQAAABAAAAAQSecureEncryptedPassword=}"
              description: "LDAP Service Account"
          - basicSSHUserPrivateKey:
              scope: GLOBAL
              id: "ssh-agent-key"
              username: "jenkins"
              description: "SSH key for Jenkins agents"
              privateKeySource:
                directEntry:
                  privateKey: |
                    -----BEGIN OPENSSH PRIVATE KEY-----
                    EncryptedPrivateKeyContentHere
                    -----END OPENSSH PRIVATE KEY-----
EOF
```

### Firewall Rules

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow from 192.168.1.0/24 to any port 8080
sudo ufw allow from 192.168.1.0/24 to any port 50000
sudo ufw reload

# firewalld (RHEL/CentOS/openSUSE)
sudo firewall-cmd --permanent --new-zone=jenkins
sudo firewall-cmd --permanent --zone=jenkins --add-source=192.168.1.0/24
sudo firewall-cmd --permanent --zone=jenkins --add-port=8080/tcp
sudo firewall-cmd --permanent --zone=jenkins --add-port=50000/tcp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 8080 -j ACCEPT
sudo iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 50000 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4

# pf (FreeBSD)
# Add to /etc/pf.conf
pass in on $ext_if proto tcp from 192.168.1.0/24 to any port {8080, 50000}

# Windows Firewall
New-NetFirewallRule -DisplayName "Jenkins HTTP" -Direction Inbound -Protocol TCP -LocalPort 8080 -RemoteAddress 192.168.1.0/24 -Action Allow
New-NetFirewallRule -DisplayName "Jenkins Agent" -Direction Inbound -Protocol TCP -LocalPort 50000 -RemoteAddress 192.168.1.0/24 -Action Allow
```

## Database Setup

### External Database Configuration (PostgreSQL)

```bash
# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Create Jenkins database
sudo -u postgres createdb jenkinsdb
sudo -u postgres createuser jenkinsuser
sudo -u postgres psql -c "ALTER USER jenkinsuser WITH PASSWORD 'SecureJenkinsPassword123!';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE jenkinsdb TO jenkinsuser;"

# Download PostgreSQL driver
wget https://jdbc.postgresql.org/download/postgresql-42.6.0.jar -O /var/lib/jenkins/postgresql-connector.jar

# Configure Jenkins to use PostgreSQL
sudo tee -a /etc/default/jenkins <<EOF
# PostgreSQL database configuration
JENKINS_JAVA_OPTIONS="-Djenkins.install.runSetupWizard=false -Dhudson.model.DirectoryBrowserSupport.CSP=\"sandbox allow-scripts; default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';\""
EOF

# Create database configuration
sudo tee /var/lib/jenkins/database-config.xml <<EOF
<databaseConfiguration>
  <database class="org.jenkinsci.plugins.database.postgresql.PostgreSQLDatabase">
    <hostname>localhost</hostname>
    <port>5432</port>
    <database>jenkinsdb</database>
    <username>jenkinsuser</username>
    <password>{AQAAABAAAAAQEncryptedPasswordHere=}</password>
    <properties>sslmode=require</properties>
  </database>
</databaseConfiguration>
EOF
```

### Backup Database Schema

```bash
# Create database schema backup
sudo -u postgres pg_dump jenkinsdb > /backup/jenkins/jenkinsdb-schema-$(date +%Y%m%d).sql

# Create Jenkins jobs and configuration backup
sudo tee /usr/local/bin/jenkins-db-backup.sh <<'EOF'
#!/bin/bash
BACKUP_DIR="/backup/jenkins/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# PostgreSQL backup
sudo -u postgres pg_dump jenkinsdb | gzip > "$BACKUP_DIR/jenkinsdb.sql.gz"

# Jenkins configuration backup
tar -czf "$BACKUP_DIR/jenkins-config.tar.gz" \
  --exclude="/var/lib/jenkins/workspace/*" \
  --exclude="/var/lib/jenkins/builds/*/archive" \
  --exclude="/var/lib/jenkins/logs/*" \
  /var/lib/jenkins/

echo "Database backup completed: $BACKUP_DIR"
EOF

chmod +x /usr/local/bin/jenkins-db-backup.sh
```

## Performance Optimization

### System Tuning

```bash
# Jenkins-specific system optimizations
sudo tee -a /etc/sysctl.conf <<EOF
# Jenkins optimizations
vm.swappiness = 1
fs.file-max = 65535
net.core.somaxconn = 32768
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.ip_local_port_range = 1024 65535
EOF

sudo sysctl -p

# Increase file descriptor limits
sudo tee -a /etc/security/limits.conf <<EOF
jenkins soft nofile 65535
jenkins hard nofile 65535
jenkins soft nproc 32768
jenkins hard nproc 32768
EOF

# Optimize Jenkins JVM settings
sudo systemctl edit jenkins
# Add:
[Service]
Environment="JAVA_OPTS=-Xmx8g -Xms4g -XX:+UseG1GC -XX:+UseStringDeduplication -XX:+DisableExplicitGC -XX:+UnlockExperimentalVMOptions -XX:+UseCGroupMemoryLimitForHeap"
Environment="JENKINS_OPTS=--sessionTimeout=1440 --sessionEviction=86400"

sudo systemctl daemon-reload
sudo systemctl restart jenkins
```

### Jenkins Performance Configuration

```bash
# Configure Jenkins for high performance
sudo tee /var/lib/jenkins/casc_configs/performance.yaml <<EOF
jenkins:
  systemMessage: "High-Performance Jenkins Instance"
  numExecutors: 0  # Don't run builds on controller
  mode: EXCLUSIVE
  quietPeriod: 5
  scmCheckoutRetryCount: 3
  
  # Global pipeline libraries for shared code
  globalLibraries:
    libraries:
      - name: "shared-pipeline-library"
        defaultVersion: "main"
        implicit: true
        retriever:
          modernSCM:
            scm:
              git:
                remote: "https://github.com/example/jenkins-shared-library.git"
                credentialsId: "github-token"

  # Configure build discarders globally
  buildDiscarders:
    configuredBuildDiscarders:
      - "logRotator":
          artifactDaysToKeepStr: "30"
          artifactNumToKeepStr: "10"
          daysToKeepStr: "30"
          numToKeepStr: "100"

unclassified:
  # Configure global timeout
  buildTimeout:
    operations:
      - timeoutMinutes: 60
      - failBuild: true
      - writingDescription: true
      
  # Workspace cleanup configuration  
  wsCleanup:
    deleteDirs: true
    cleanupMatrixParent: true
    skipWhenFailed: false
    
tool:
  # Configure tools for performance
  git:
    installations:
      - name: "Default"
        home: "/usr/bin/git"
        
  maven:
    installations:
      - name: "Maven 3.9"
        properties:
          - installSource:
              installers:
                - maven:
                    id: "3.9.6"
                    
  gradle:
    installations:
      - name: "Gradle 8"
        properties:
          - installSource:
              installers:
                - gradleInstaller:
                    id: "8.4"

  nodejs:
    installations:
      - name: "NodeJS 18"
        properties:
          - installSource:
              installers:
                - nodeJSInstaller:
                    id: "18.18.2"
                    
  dockerTool:
    installations:
      - name: "Docker"
        properties:
          - installSource:
              installers:
                - dockerInstaller:
                    version: "latest"
EOF

# Configure agent templates for auto-scaling
sudo tee /var/lib/jenkins/casc_configs/agents.yaml <<EOF
jenkins:
  clouds:
    - kubernetes:
        name: "kubernetes"
        serverUrl: "https://kubernetes.default.svc.cluster.local"
        namespace: "jenkins"
        credentialsId: "kubernetes-token"
        jenkinsUrl: "http://jenkins.jenkins.svc.cluster.local:8080"
        jenkinsTunnel: "jenkins-agent.jenkins.svc.cluster.local:50000"
        connectTimeout: 300
        readTimeout: 300
        containerCapStr: 100
        templates:
          - name: "jenkins-agent"
            namespace: "jenkins"
            label: "kubernetes docker"
            nodeUsageMode: EXCLUSIVE
            containers:
              - name: "jnlp"
                image: "jenkins/inbound-agent:latest"
                alwaysPullImage: true
                workingDir: "/home/jenkins/agent"
                command: ""
                args: ""
                resourceRequestCpu: "500m"
                resourceRequestMemory: "1Gi"
                resourceLimitCpu: "2"
                resourceLimitMemory: "4Gi"
            volumes:
              - hostPathVolume:
                  hostPath: "/var/run/docker.sock"
                  mountPath: "/var/run/docker.sock"
EOF
```

### Pipeline Optimization

```groovy
// Optimized Jenkins Pipeline Template
// /var/lib/jenkins/pipeline-templates/optimized-pipeline.groovy
@Library('shared-pipeline-library') _

pipeline {
    agent {
        label 'docker && linux'
    }
    
    options {
        buildDiscarder(logRotator(numToKeepStr: '50', artifactNumToKeepStr: '10'))
        timeout(time: 120, unit: 'MINUTES')
        timestamps()
        skipDefaultCheckout(true)
        disableConcurrentBuilds()
        ansiColor('xterm')
        parallelsAlwaysFailFast()
        copyArtifactPermission('*')
    }
    
    environment {
        DOCKER_REGISTRY = credentials('docker-registry-url')
        MAVEN_OPTS = '-Xmx2g -XX:+UseG1GC'
        GRADLE_OPTS = '-Xmx2g -Dorg.gradle.daemon=false'
        CI = 'true'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.GIT_COMMIT_SHORT = env.GIT_COMMIT.take(8)
                    env.BUILD_VERSION = "${env.BUILD_NUMBER}-${env.GIT_COMMIT_SHORT}"
                }
            }
        }
        
        stage('Parallel Analysis') {
            parallel {
                stage('Code Quality') {
                    steps {
                        script {
                            // SonarQube analysis
                            withSonarQubeEnv('SonarQube') {
                                sh '''
                                    mvn sonar:sonar \
                                        -Dsonar.projectKey=${JOB_NAME} \
                                        -Dsonar.projectVersion=${BUILD_VERSION} \
                                        -Dsonar.sources=src/main \
                                        -Dsonar.tests=src/test \
                                        -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml
                                '''
                            }
                            
                            timeout(time: 10, unit: 'MINUTES') {
                                waitForQualityGate abortPipeline: true
                            }
                        }
                    }
                }
                
                stage('Security Scan') {
                    steps {
                        // OWASP Dependency Check
                        dependencyCheck additionalArguments: '''
                            --enableRetired
                            --enableExperimental  
                            --scan ./
                            --format JSON
                            --format HTML
                            --suppression dependency-check-suppressions.xml
                        ''', odcInstallation: 'dependency-check-8.4.0'
                        
                        dependencyCheckPublisher pattern: '**/dependency-check-report.xml'
                        
                        // Secret scanning
                        sh '''
                            docker run --rm -v $(pwd):/repo \
                                trufflesecurity/trufflehog:latest \
                                git file:///repo \
                                --json \
                                --fail > trufflehog-results.json || true
                        '''
                    }
                }
                
                stage('Test') {
                    steps {
                        sh '''
                            # Parallel test execution
                            mvn clean test \
                                -Dmaven.test.failure.ignore=true \
                                -Dspring.profiles.active=test \
                                -Djunit.jupiter.execution.parallel.enabled=true \
                                -Djunit.jupiter.execution.parallel.mode.default=concurrent
                        '''
                        
                        publishTestResults testResultsPattern: 'target/surefire-reports/*.xml'
                        publishCoverage adapters: [jacocoAdapter('target/site/jacoco/jacoco.xml')], 
                                       sourceFileResolver: sourceFiles('STORE_LAST_BUILD')
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'target/surefire-reports/**', allowEmptyArchive: true
                        }
                    }
                }
            }
        }
        
        stage('Build & Package') {
            steps {
                sh '''
                    # Optimized build with parallel processing
                    mvn clean package \
                        -DskipTests \
                        -T 2C \
                        -Dspring.profiles.active=production \
                        -Dmaven.javadoc.skip=true
                '''
                
                // Docker build with BuildKit
                script {
                    def image = docker.build("${env.DOCKER_REGISTRY}/${env.JOB_NAME}:${env.BUILD_VERSION}", 
                                           "--build-arg BUILD_VERSION=${env.BUILD_VERSION} .")
                    
                    // Security scanning with Trivy
                    sh """
                        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
                            aquasec/trivy:latest image \
                            --format table \
                            --severity HIGH,CRITICAL \
                            --exit-code 1 \
                            ${env.DOCKER_REGISTRY}/${env.JOB_NAME}:${env.BUILD_VERSION}
                    """
                    
                    image.push()
                    image.push("latest")
                }
            }
        }
        
        stage('Deploy') {
            when {
                anyOf {
                    branch 'main'
                    branch 'develop'
                    branch 'release/*'
                }
            }
            parallel {
                stage('Staging') {
                    when { branch 'develop' }
                    steps {
                        script {
                            // Deploy to staging environment
                            sh '''
                                kubectl set image deployment/myapp-staging \
                                    myapp=${DOCKER_REGISTRY}/${JOB_NAME}:${BUILD_VERSION} \
                                    --namespace=staging
                                
                                kubectl rollout status deployment/myapp-staging \
                                    --namespace=staging --timeout=300s
                            '''
                            
                            // Run smoke tests
                            sh '''
                                curl -f http://myapp-staging.example.com/health || exit 1
                                npm run test:e2e -- --base-url http://myapp-staging.example.com
                            '''
                        }
                    }
                }
                
                stage('Production') {
                    when { 
                        anyOf {
                            branch 'main'
                            branch 'release/*'
                        }
                    }
                    steps {
                        // Manual approval for production
                        timeout(time: 60, unit: 'MINUTES') {
                            input message: 'Deploy to production?', 
                                  ok: 'Deploy',
                                  submitterParameter: 'APPROVER'
                        }
                        
                        script {
                            sh '''
                                # Blue-green deployment
                                kubectl set image deployment/myapp-production \
                                    myapp=${DOCKER_REGISTRY}/${JOB_NAME}:${BUILD_VERSION} \
                                    --namespace=production
                                
                                kubectl rollout status deployment/myapp-production \
                                    --namespace=production --timeout=600s
                            '''
                        }
                    }
                }
            }
        }
    }
    
    post {
        always {
            // Cleanup workspace
            cleanWs()
            
            // Archive artifacts
            archiveArtifacts artifacts: 'target/*.jar,docker-compose.yml', 
                           allowEmptyArchive: true, 
                           fingerprint: true
                           
            // Collect build metrics
            script {
                def buildDuration = currentBuild.duration / 1000
                echo "Build completed in ${buildDuration} seconds"
                
                // Custom metrics collection
                sh """
                    echo "build_duration_seconds{job=\"${env.JOB_NAME}\",build=\"${env.BUILD_NUMBER}\"} ${buildDuration}" > build-metrics.txt
                """
                
                archiveArtifacts artifacts: 'build-metrics.txt', allowEmptyArchive: true
            }
        }
        
        success {
            // Success notifications
            emailext(
                subject: "✅ Build Success: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: """Build successful for ${env.JOB_NAME} build ${env.BUILD_NUMBER}
                         
                Build URL: ${env.BUILD_URL}
                Git Commit: ${env.GIT_COMMIT}
                Duration: ${currentBuild.durationString}
                Approver: ${env.APPROVER ?: 'Automatic'}""",
                to: "${env.CHANGE_AUTHOR_EMAIL ?: 'jenkins@example.com'}"
            )
            
            slackSend(
                channel: '#deployments',
                color: 'good',
                message: "✅ Deployment Success: ${env.JOB_NAME} - ${env.BUILD_NUMBER} by ${env.APPROVER ?: 'System'}"
            )
        }
        
        failure {
            emailext(
                subject: "❌ Build Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "Build failed for ${env.JOB_NAME} build ${env.BUILD_NUMBER}\n\nBuild URL: ${env.BUILD_URL}",
                to: "${env.CHANGE_AUTHOR_EMAIL ?: 'jenkins@example.com'}"
            )
            
            slackSend(
                channel: '#ci-cd-alerts',
                color: 'danger',
                message: "❌ Build Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER} (<${env.BUILD_URL}|View Details>)"
            )
        }
        
        unstable {
            emailext(
                subject: "⚠️  Build Unstable: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "Build unstable for ${env.JOB_NAME} build ${env.BUILD_NUMBER}\n\nBuild URL: ${env.BUILD_URL}",
                to: "${env.CHANGE_AUTHOR_EMAIL ?: 'jenkins@example.com'}"
            )
        }
    }
}
```

## Monitoring

### Built-in Monitoring

```bash
# Jenkins CLI monitoring commands
java -jar jenkins-cli.jar -s http://localhost:8080 -auth admin:password version
java -jar jenkins-cli.jar -s http://localhost:8080 -auth admin:password list-jobs
java -jar jenkins-cli.jar -s http://localhost:8080 -auth admin:password list-builds job-name
java -jar jenkins-cli.jar -s http://localhost:8080 -auth admin:password get-build job-name 1

# System information
curl -u admin:password http://localhost:8080/systemInfo

# Build queue status
curl -u admin:password http://localhost:8080/queue/api/json

# Node status
curl -u admin:password http://localhost:8080/computer/api/json

# Plugin information
curl -u admin:password http://localhost:8080/pluginManager/api/json?depth=1
```

### External Monitoring Setup

```bash
# Install Jenkins Prometheus Plugin and configure metrics
# Via Jenkins UI: Manage Jenkins > Manage Plugins > Available > Prometheus metrics plugin

# Configure Prometheus to scrape Jenkins metrics
sudo tee /etc/prometheus/jenkins.yml <<EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'jenkins'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: /prometheus/
    scrape_interval: 30s
    scrape_timeout: 10s
EOF

# Install Jenkins Exporter (alternative)
wget https://github.com/lovoo/jenkins_exporter/releases/download/v1.0.0/jenkins_exporter-1.0.0.linux-amd64.tar.gz
tar xzf jenkins_exporter-*.tar.gz
sudo cp jenkins_exporter /usr/local/bin/

# Create systemd service
sudo tee /etc/systemd/system/jenkins_exporter.service <<EOF
[Unit]
Description=Jenkins Exporter
After=network.target

[Service]
Type=simple
User=jenkins
ExecStart=/usr/local/bin/jenkins_exporter \
    --jenkins.address=http://localhost:8080 \
    --jenkins.username=monitoring \
    --jenkins.password=MonitoringPassword123! \
    --web.listen-address=:9118
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now jenkins_exporter
```

### Health Check Scripts

```bash
#!/bin/bash
# jenkins-health-check.sh

JENKINS_URL="http://localhost:8080"
HEALTH_LOG="/var/log/jenkins-health.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a ${HEALTH_LOG}
}

# Check service status
if systemctl is-active jenkins >/dev/null 2>&1; then
    log_message "✅ Jenkins service is running"
else
    log_message "❌ Jenkins service is not running"
    exit 2
fi

# Check web interface
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" ${JENKINS_URL}/login)
if [ "${HTTP_STATUS}" = "200" ]; then
    log_message "✅ Jenkins web interface responding (HTTP ${HTTP_STATUS})"
else
    log_message "❌ Jenkins web interface issues (HTTP ${HTTP_STATUS})"
    exit 2
fi

# Check disk space
JENKINS_HOME_USAGE=$(df /var/lib/jenkins | awk 'NR==2 {print $5}' | sed 's/%//')
if [ ${JENKINS_HOME_USAGE} -gt 85 ]; then
    log_message "⚠️  High disk usage: ${JENKINS_HOME_USAGE}%"
    exit 1
else
    log_message "✅ Jenkins home disk usage: ${JENKINS_HOME_USAGE}%"
fi

# Check memory usage
JAVA_MEMORY=$(ps -o pid,vsz,rss,comm -C java | grep jenkins | awk '{rss+=$3} END {print rss/1024}')
if (( $(echo "${JAVA_MEMORY} > 6144" | bc -l) )); then
    log_message "⚠️  High memory usage: ${JAVA_MEMORY}MB"
    exit 1
else
    log_message "✅ Jenkins memory usage: ${JAVA_MEMORY}MB"
fi

# Check running builds (if Jenkins CLI is available)
if [ -f /var/lib/jenkins/jenkins-cli.jar ]; then
    RUNNING_BUILDS=$(java -jar /var/lib/jenkins/jenkins-cli.jar -s ${JENKINS_URL} -auth monitoring:MonitoringPassword123! list-builds 2>/dev/null | grep -c "RUNNING" || echo "0")
    log_message "ℹ️  Running builds: ${RUNNING_BUILDS}"
    
    # Check for failed builds in last 24 hours
    FAILED_BUILDS=$(java -jar /var/lib/jenkins/jenkins-cli.jar -s ${JENKINS_URL} -auth monitoring:MonitoringPassword123! list-builds 2>/dev/null | grep -c "FAILURE" || echo "0")
    if [ ${FAILED_BUILDS} -gt 5 ]; then
        log_message "⚠️  High number of failed builds: ${FAILED_BUILDS}"
        exit 1
    fi
fi

# Check plugin health
PLUGIN_ERRORS=$(curl -s ${JENKINS_URL}/pluginManager/api/json?depth=1 | jq '.plugins[] | select(.hasUpdate==true or .enabled==false) | .shortName' | wc -l)
if [ ${PLUGIN_ERRORS} -gt 0 ]; then
    log_message "⚠️  Plugins need attention: ${PLUGIN_ERRORS}"
fi

log_message "✅ Jenkins health check completed"
exit 0
```

## 9. Backup and Restore

### Comprehensive Backup Strategy

```bash
#!/bin/bash
# jenkins-backup.sh

BACKUP_DIR="/backup/jenkins"
DATE=$(date +%Y%m%d_%H%M%S)
JENKINS_HOME="/var/lib/jenkins"
RETENTION_DAYS=14

mkdir -p ${BACKUP_DIR}/{config,jobs,plugins,secrets,workspace}

echo "Starting Jenkins comprehensive backup..."

# Function to gracefully shutdown Jenkins
graceful_shutdown() {
    echo "Putting Jenkins in quiet mode..."
    java -jar ${JENKINS_HOME}/jenkins-cli.jar -s http://localhost:8080 -auth admin:SecureAdminPassword123! quiet-down
    
    # Wait for running builds to complete (max 20 minutes)
    for i in {1..120}; do
        RUNNING_BUILDS=$(java -jar ${JENKINS_HOME}/jenkins-cli.jar -s http://localhost:8080 -auth admin:SecureAdminPassword123! list-builds | grep -c "RUNNING" || echo "0")
        if [ "$RUNNING_BUILDS" -eq 0 ]; then
            echo "All builds completed, stopping Jenkins..."
            systemctl stop jenkins
            break
        fi
        echo "Waiting for $RUNNING_BUILDS running builds to complete... (${i}/120)"
        sleep 10
    done
    
    if [ "$RUNNING_BUILDS" -gt 0 ]; then
        echo "Warning: Stopping Jenkins with $RUNNING_BUILDS builds still running"
        systemctl stop jenkins
    fi
}

# Function to start Jenkins
start_jenkins() {
    echo "Starting Jenkins..."
    systemctl start jenkins
    
    # Wait for Jenkins to be ready
    for i in {1..60}; do
        if curl -f http://localhost:8080/login >/dev/null 2>&1; then
            echo "Jenkins is ready, canceling quiet mode..."
            java -jar ${JENKINS_HOME}/jenkins-cli.jar -s http://localhost:8080 -auth admin:SecureAdminPassword123! cancel-quiet-down
            break
        fi
        echo "Waiting for Jenkins to start... (${i}/60)"
        sleep 10
    done
}

# Gracefully shutdown Jenkins
graceful_shutdown

# Full Jenkins home backup (excluding large/temporary directories)
echo "Creating full Jenkins home backup..."
tar --exclude="${JENKINS_HOME}/workspace/*" \
    --exclude="${JENKINS_HOME}/builds/*/archive" \
    --exclude="${JENKINS_HOME}/logs/*" \
    --exclude="${JENKINS_HOME}/.m2/repository" \
    --exclude="${JENKINS_HOME}/caches" \
    --exclude="${JENKINS_HOME}/war" \
    -czf ${BACKUP_DIR}/config/jenkins-home-${DATE}.tar.gz \
    -C ${JENKINS_HOME} .

# Job configurations backup
echo "Backing up job configurations..."
mkdir -p ${BACKUP_DIR}/jobs
find ${JENKINS_HOME}/jobs -name "config.xml" -exec cp {} ${BACKUP_DIR}/jobs/ \;
tar -czf ${BACKUP_DIR}/jobs/job-configs-${DATE}.tar.gz -C ${BACKUP_DIR}/jobs .
rm ${BACKUP_DIR}/jobs/config.xml 2>/dev/null

# Plugins backup
echo "Backing up installed plugins..."
java -jar ${JENKINS_HOME}/jenkins-cli.jar -s http://localhost:8080 -auth admin:SecureAdminPassword123! list-plugins > ${BACKUP_DIR}/plugins/plugin-list-${DATE}.txt
cp -r ${JENKINS_HOME}/plugins ${BACKUP_DIR}/plugins/plugins-${DATE}/ 2>/dev/null

# Secrets and credentials backup
echo "Backing up secrets and credentials..."
if [ -d "${JENKINS_HOME}/secrets" ]; then
    tar -czf ${BACKUP_DIR}/secrets/jenkins-secrets-${DATE}.tar.gz -C ${JENKINS_HOME} secrets/
fi

# System configuration backup
echo "Backing up system configuration..."
tar -czf ${BACKUP_DIR}/config/system-config-${DATE}.tar.gz \
    /etc/default/jenkins \
    /etc/sysconfig/jenkins \
    /etc/systemd/system/jenkins.service.d/ 2>/dev/null

# Database backup (if using external database)
if [ -f "${JENKINS_HOME}/database-config.xml" ]; then
    echo "Backing up external database..."
    sudo -u postgres pg_dump jenkinsdb | gzip > ${BACKUP_DIR}/config/jenkinsdb-${DATE}.sql.gz
fi

# Start Jenkins
start_jenkins

# Cloud backup (uncomment and configure as needed)
# aws s3 cp ${BACKUP_DIR}/ s3://jenkins-backups/${DATE}/ --recursive --sse AES256
# az storage blob upload-batch --source ${BACKUP_DIR} --destination jenkins-backups --destination-path ${DATE}
# gsutil cp -r ${BACKUP_DIR}/* gs://jenkins-backups/${DATE}/

# Verify backup integrity
echo "Verifying backup integrity..."
LATEST_BACKUP=$(ls -t ${BACKUP_DIR}/config/jenkins-home-*.tar.gz | head -1)
if tar -tzf "$LATEST_BACKUP" >/dev/null 2>&1; then
    echo "✅ Backup integrity verified"
    BACKUP_SIZE=$(du -h "$LATEST_BACKUP" | cut -f1)
    echo "Backup size: $BACKUP_SIZE"
else
    echo "❌ Backup integrity check failed"
    exit 1
fi

# Cleanup old backups
echo "Cleaning up old backups (keeping last $RETENTION_DAYS days)..."
find ${BACKUP_DIR} -name "jenkins-*" -type f -mtime +${RETENTION_DAYS} -delete
find ${BACKUP_DIR} -name "plugin-list-*" -type f -mtime +${RETENTION_DAYS} -delete
find ${BACKUP_DIR} -name "*-${DATE}*" -type d -mtime +${RETENTION_DAYS} -exec rm -rf {} \;

# Generate backup report
echo "Generating backup report..."
cat > ${BACKUP_DIR}/backup-report-${DATE}.txt <<EOF
Jenkins Backup Report - ${DATE}
================================

Backup Location: ${BACKUP_DIR}
Jenkins Home: ${JENKINS_HOME}
Backup Date: $(date)
Server: $(hostname)

Files backed up:
- Jenkins Home: $(ls -lh ${BACKUP_DIR}/config/jenkins-home-${DATE}.tar.gz)
- Job Configs: $(ls -lh ${BACKUP_DIR}/jobs/job-configs-${DATE}.tar.gz)
- Plugins: $(ls -lh ${BACKUP_DIR}/plugins/plugin-list-${DATE}.txt)
- Secrets: $(ls -lh ${BACKUP_DIR}/secrets/jenkins-secrets-${DATE}.tar.gz 2>/dev/null || echo "No secrets backup")
- System Config: $(ls -lh ${BACKUP_DIR}/config/system-config-${DATE}.tar.gz 2>/dev/null || echo "No system config backup")

Total Backup Size: $(du -h ${BACKUP_DIR} | tail -1 | cut -f1)

Verification: ✅ Passed
EOF

echo "✅ Jenkins backup completed: ${DATE}"
echo "📊 Backup report: ${BACKUP_DIR}/backup-report-${DATE}.txt"
```

### Restore Procedures

```bash
#!/bin/bash
# jenkins-restore.sh

BACKUP_FILE="${1}"
RESTORE_TYPE="${2:-full}"  # full, config-only, jobs-only

usage() {
    echo "Usage: $0 <backup_file> [restore_type]"
    echo "Restore types: full (default), config-only, jobs-only"
    echo ""
    echo "Available backups:"
    ls -la /backup/jenkins/config/jenkins-home-*.tar.gz | head -10
    exit 1
}

if [ -z "$BACKUP_FILE" ]; then
    usage
fi

if [ ! -f "$BACKUP_FILE" ]; then
    echo "❌ Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "🔄 Starting Jenkins restore from: $BACKUP_FILE"
echo "Restore type: $RESTORE_TYPE"

# Pre-restore backup of current state
if [ -d "/var/lib/jenkins" ]; then
    echo "📦 Creating backup of current installation..."
    CURRENT_BACKUP="/backup/jenkins/pre-restore-$(date +%s)"
    mkdir -p "$CURRENT_BACKUP"
    mv /var/lib/jenkins "$CURRENT_BACKUP/jenkins-$(date +%Y%m%d_%H%M%S)"
    echo "Current installation backed up to: $CURRENT_BACKUP"
fi

# Stop Jenkins
echo "⏹️  Stopping Jenkins..."
systemctl stop jenkins

case "$RESTORE_TYPE" in
    "full")
        echo "🔄 Performing full restore..."
        
        # Create new Jenkins directory
        mkdir -p /var/lib/jenkins
        
        # Restore from backup
        echo "📂 Extracting backup archive..."
        tar -xzf "$BACKUP_FILE" -C /var/lib/jenkins
        
        # Set proper ownership
        chown -R jenkins:jenkins /var/lib/jenkins
        chmod -R 755 /var/lib/jenkins
        
        # Special permissions for secrets
        if [ -d "/var/lib/jenkins/secrets" ]; then
            chmod 700 /var/lib/jenkins/secrets
            chmod 600 /var/lib/jenkins/secrets/*
        fi
        ;;
        
    "config-only")
        echo "🔄 Performing configuration-only restore..."
        
        # Create minimal Jenkins directory
        mkdir -p /var/lib/jenkins
        
        # Extract only configuration files
        tar -xzf "$BACKUP_FILE" -C /var/lib/jenkins \
            --include="*/config.xml" \
            --include="*/secrets/*" \
            --include="*/users/*" \
            --include="*/plugins/*" \
            --exclude="*/workspace/*" \
            --exclude="*/builds/*"
            
        chown -R jenkins:jenkins /var/lib/jenkins
        ;;
        
    "jobs-only")
        echo "🔄 Performing jobs-only restore..."
        
        if [ ! -d "/var/lib/jenkins" ]; then
            echo "❌ Jenkins directory not found. Cannot restore jobs only."
            exit 1
        fi
        
        # Backup current jobs
        if [ -d "/var/lib/jenkins/jobs" ]; then
            mv /var/lib/jenkins/jobs "/var/lib/jenkins/jobs.backup.$(date +%s)"
        fi
        
        # Extract only jobs
        tar -xzf "$BACKUP_FILE" -C /var/lib/jenkins jobs/
        chown -R jenkins:jenkins /var/lib/jenkins/jobs
        ;;
        
    *)
        echo "❌ Unknown restore type: $RESTORE_TYPE"
        usage
        ;;
esac

# Restore system configuration if available
BACKUP_DIR=$(dirname "$BACKUP_FILE")
BACKUP_DATE=$(basename "$BACKUP_FILE" .tar.gz | sed 's/jenkins-home-//')
SYSTEM_CONFIG="${BACKUP_DIR}/../config/system-config-${BACKUP_DATE}.tar.gz"

if [ -f "$SYSTEM_CONFIG" ]; then
    echo "🔧 Restoring system configuration..."
    tar -xzf "$SYSTEM_CONFIG" -C / 2>/dev/null
    systemctl daemon-reload
fi

# Restore database if available
DB_BACKUP="${BACKUP_DIR}/jenkinsdb-${BACKUP_DATE}.sql.gz"
if [ -f "$DB_BACKUP" ]; then
    echo "🗄️  Restoring database..."
    zcat "$DB_BACKUP" | sudo -u postgres psql jenkinsdb
fi

# Start Jenkins
echo "▶️  Starting Jenkins..."
systemctl start jenkins

# Wait for Jenkins to start and verify
echo "⏳ Waiting for Jenkins to start..."
for i in {1..120}; do
    if curl -f http://localhost:8080/login >/dev/null 2>&1; then
        echo "✅ Jenkins started successfully"
        break
    fi
    echo "Waiting for Jenkins to start... (${i}/120)"
    sleep 10
done

# Verify restoration
echo "🔍 Verifying restoration..."
if curl -f http://localhost:8080/login >/dev/null 2>&1; then
    echo "✅ Jenkins is responding"
    
    # Check if jobs were restored
    if [ -d "/var/lib/jenkins/jobs" ]; then
        JOB_COUNT=$(ls -1 /var/lib/jenkins/jobs | wc -l)
        echo "📋 Jobs restored: $JOB_COUNT"
    fi
    
    # Check if plugins were restored
    if [ -d "/var/lib/jenkins/plugins" ]; then
        PLUGIN_COUNT=$(ls -1 /var/lib/jenkins/plugins | wc -l)
        echo "🔌 Plugins restored: $PLUGIN_COUNT"
    fi
    
    echo "✅ Jenkins restoration completed successfully"
    echo ""
    echo "📝 Next steps:"
    echo "1. Verify Jenkins configuration via web interface"
    echo "2. Check plugin compatibility and update if needed"
    echo "3. Verify job configurations and test builds"
    echo "4. Update any environment-specific settings"
    
else
    echo "❌ Jenkins restoration failed - service not responding"
    echo "Check logs: journalctl -u jenkins -n 50"
    exit 1
fi
```

### Disaster Recovery

```bash
#!/bin/bash
# jenkins-disaster-recovery.sh

echo "🚨 Jenkins Disaster Recovery Procedure"
echo "======================================"

# Check if Jenkins is running
if systemctl is-active jenkins >/dev/null 2>&1; then
    echo "⚠️  Jenkins is running. This procedure should be run on a failed system."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Find latest backup
BACKUP_DIR="/backup/jenkins"
LATEST_BACKUP=$(ls -t ${BACKUP_DIR}/config/jenkins-home-*.tar.gz 2>/dev/null | head -1)

if [ -z "$LATEST_BACKUP" ]; then
    echo "❌ No backups found in ${BACKUP_DIR}"
    echo "Please restore from cloud backup or external storage"
    exit 1
fi

echo "📦 Latest backup found: $LATEST_BACKUP"
echo "📅 Backup date: $(basename "$LATEST_BACKUP" .tar.gz | sed 's/jenkins-home-//')"

# Verify backup integrity
echo "🔍 Verifying backup integrity..."
if tar -tzf "$LATEST_BACKUP" >/dev/null 2>&1; then
    echo "✅ Backup integrity verified"
else
    echo "❌ Backup is corrupted. Cannot proceed with recovery."
    exit 1
fi

# Create disaster recovery log
DR_LOG="/var/log/jenkins-disaster-recovery-$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$DR_LOG")
exec 2>&1

echo "📝 Disaster recovery log: $DR_LOG"

# System preparation
echo "🔧 Preparing system for recovery..."

# Install Jenkins if not present
if ! command -v jenkins >/dev/null 2>&1; then
    echo "📦 Installing Jenkins..."
    # Add Jenkins repository and install (distribution-specific commands)
    if [ -f /etc/debian_version ]; then
        wget -q -O - https://pkg.jenkins.io/debian-stable/jenkins.io.key | apt-key add -
        echo "deb https://pkg.jenkins.io/debian-stable binary/" > /etc/apt/sources.list.d/jenkins.list
        apt-get update
        apt-get install -y openjdk-17-jdk jenkins
    elif [ -f /etc/redhat-release ]; then
        yum install -y java-17-openjdk jenkins
    fi
fi

# Stop Jenkins service
systemctl stop jenkins

# Clear existing Jenkins data
if [ -d "/var/lib/jenkins" ]; then
    echo "🗑️  Removing existing Jenkins data..."
    rm -rf /var/lib/jenkins.disaster-backup-$(date +%s)
    mv /var/lib/jenkins /var/lib/jenkins.disaster-backup-$(date +%s)
fi

# Create new Jenkins directory
mkdir -p /var/lib/jenkins

# Restore from backup
echo "🔄 Restoring Jenkins from backup..."
tar -xzf "$LATEST_BACKUP" -C /var/lib/jenkins

# Set proper permissions
chown -R jenkins:jenkins /var/lib/jenkins
chmod -R 755 /var/lib/jenkins

# Special permissions for sensitive files
if [ -d "/var/lib/jenkins/secrets" ]; then
    chmod 700 /var/lib/jenkins/secrets
    chmod 600 /var/lib/jenkins/secrets/*
fi

if [ -d "/var/lib/jenkins/users" ]; then
    chmod 700 /var/lib/jenkins/users
fi

# Restore system configuration
BACKUP_DATE=$(basename "$LATEST_BACKUP" .tar.gz | sed 's/jenkins-home-//')
SYSTEM_CONFIG="${BACKUP_DIR}/config/system-config-${BACKUP_DATE}.tar.gz"

if [ -f "$SYSTEM_CONFIG" ]; then
    echo "🔧 Restoring system configuration..."
    tar -xzf "$SYSTEM_CONFIG" -C / 2>/dev/null
    systemctl daemon-reload
fi

# Restore database if available
DB_BACKUP="${BACKUP_DIR}/config/jenkinsdb-${BACKUP_DATE}.sql.gz"
if [ -f "$DB_BACKUP" ]; then
    echo "🗄️  Restoring database..."
    # Ensure PostgreSQL is running
    systemctl start postgresql
    
    # Drop and recreate database
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS jenkinsdb;"
    sudo -u postgres psql -c "CREATE DATABASE jenkinsdb;"
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE jenkinsdb TO jenkinsuser;"
    
    # Restore database
    zcat "$DB_BACKUP" | sudo -u postgres psql jenkinsdb
fi

# Configure firewall
echo "🔥 Configuring firewall..."
if command -v ufw >/dev/null 2>&1; then
    ufw allow 8080/tcp
    ufw allow 50000/tcp
elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=8080/tcp
    firewall-cmd --permanent --add-port=50000/tcp
    firewall-cmd --reload
fi

# Start Jenkins
echo "▶️  Starting Jenkins..."
systemctl enable jenkins
systemctl start jenkins

# Wait for Jenkins to start
echo "⏳ Waiting for Jenkins to initialize..."
for i in {1..300}; do
    if curl -f http://localhost:8080/login >/dev/null 2>&1; then
        echo "✅ Jenkins is responding"
        break
    fi
    echo "Waiting for Jenkins... (${i}/300)"
    sleep 10
done

# Verify recovery
echo "🔍 Verifying disaster recovery..."

# Check Jenkins status
if systemctl is-active jenkins >/dev/null 2>&1; then
    echo "✅ Jenkins service is running"
else
    echo "❌ Jenkins service failed to start"
    echo "Check logs: journalctl -u jenkins -n 50"
    exit 1
fi

# Check web interface
if curl -f http://localhost:8080/login >/dev/null 2>&1; then
    echo "✅ Jenkins web interface is accessible"
else
    echo "❌ Jenkins web interface is not responding"
    exit 1
fi

# Check jobs restoration
if [ -d "/var/lib/jenkins/jobs" ]; then
    JOB_COUNT=$(ls -1 /var/lib/jenkins/jobs 2>/dev/null | wc -l)
    echo "📋 Jobs recovered: $JOB_COUNT"
else
    echo "⚠️  No jobs directory found"
fi

# Check plugins restoration
if [ -d "/var/lib/jenkins/plugins" ]; then
    PLUGIN_COUNT=$(ls -1 /var/lib/jenkins/plugins 2>/dev/null | wc -l)
    echo "🔌 Plugins recovered: $PLUGIN_COUNT"
else
    echo "⚠️  No plugins directory found"
fi

# Generate recovery report
echo "📊 Generating disaster recovery report..."
cat > "/var/log/jenkins-recovery-report-$(date +%Y%m%d_%H%M%S).txt" <<EOF
Jenkins Disaster Recovery Report
===============================
Recovery Date: $(date)
Server: $(hostname)
Backup Used: $LATEST_BACKUP
Recovery Log: $DR_LOG

Recovery Summary:
- Jenkins Service: $(systemctl is-active jenkins)
- Web Interface: $(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/login)
- Jobs Recovered: $JOB_COUNT
- Plugins Recovered: $PLUGIN_COUNT
- Database Restored: $([ -f "$DB_BACKUP" ] && echo "Yes" || echo "No")

Next Steps:
1. Verify Jenkins configuration via web interface: http://$(hostname):8080
2. Test critical job configurations
3. Update any environment-specific settings
4. Verify agent connections
5. Test integrations (SCM, notifications, etc.)
6. Update DNS/load balancer configurations if needed
7. Notify team of recovery completion

Recovery Status: ✅ COMPLETED
EOF

echo ""
echo "🎉 Jenkins disaster recovery completed successfully!"
echo "📝 Recovery report saved to: /var/log/jenkins-recovery-report-$(date +%Y%m%d_%H%M%S).txt"
echo ""
echo "🔗 Access Jenkins: http://$(hostname):8080"
echo ""
echo "⚠️  Important post-recovery tasks:"
echo "1. Verify all job configurations"
echo "2. Test agent connections"
echo "3. Verify integrations (GitHub, LDAP, etc.)"
echo "4. Update any environment-specific configurations"
echo "5. Perform a backup of the recovered system"
```

## 6. Troubleshooting

### Common Issues

1. **Jenkins won't start**:
```bash
# Check service status and logs
sudo systemctl status jenkins
sudo journalctl -u jenkins -f

# Check Java version and JAVA_HOME
java -version
echo $JAVA_HOME

# Check disk space
df -h /var/lib/jenkins

# Check permissions
ls -la /var/lib/jenkins
sudo chown -R jenkins:jenkins /var/lib/jenkins

# Check memory allocation
free -h
ps aux | grep jenkins

# Clear Jenkins cache
sudo systemctl stop jenkins
sudo rm -rf /var/lib/jenkins/war
sudo systemctl start jenkins
```

2. **Memory issues**:
```bash
# Increase JVM memory
sudo systemctl edit jenkins
# Add:
[Service]
Environment="JAVA_OPTS=-Xmx8g -Xms4g -XX:+UseG1GC"

sudo systemctl daemon-reload
sudo systemctl restart jenkins

# Monitor memory usage
top -p $(pgrep java)
jstat -gc $(pgrep java) 5s
```

3. **Plugin issues**:
```bash
# Safe start (disable all plugins)
sudo systemctl stop jenkins
echo 'jenkins.install.runSetupWizard=false' > /var/lib/jenkins/jenkins.install.runSetupWizard
sudo systemctl start jenkins

# Clear plugin cache
sudo rm -rf /var/lib/jenkins/plugins/*.bak
sudo rm -rf /var/lib/jenkins/plugins/*.hpi.pinned

# Update plugins via CLI
java -jar jenkins-cli.jar -s http://localhost:8080 -auth admin:password list-plugins | grep -E "\)$" | awk '{print $1}' | xargs java -jar jenkins-cli.jar -s http://localhost:8080 -auth admin:password install-plugin

# Check plugin dependencies
java -jar jenkins-cli.jar -s http://localhost:8080 -auth admin:password list-plugins | grep -v "^$"
```

4. **Build failures**:
```bash
# Check workspace permissions
sudo chown -R jenkins:jenkins /var/lib/jenkins/workspace

# Clear old builds
java -jar jenkins-cli.jar -s http://localhost:8080 -auth admin:password delete-builds job-name 1-100

# Check agent connectivity
java -jar jenkins-cli.jar -s http://localhost:8080 -auth admin:password list-computers
java -jar jenkins-cli.jar -s http://localhost:8080 -auth admin:password connect-node agent-name

# Monitor build resources
htop
iostat -x 1
```

### Debug Mode

```bash
# Enable debug logging for Jenkins
sudo systemctl edit jenkins
# Add:
[Service]
Environment="JAVA_OPTS=-Xmx4g -Djava.util.logging.config.file=/var/lib/jenkins/logging.properties"

# Create detailed logging configuration
sudo tee /var/lib/jenkins/logging.properties <<EOF
.level = INFO

# Root logger
handlers = java.util.logging.ConsoleHandler, java.util.logging.FileHandler

# Console logging
java.util.logging.ConsoleHandler.level = INFO
java.util.logging.ConsoleHandler.formatter = java.util.logging.SimpleFormatter

# File logging
java.util.logging.FileHandler.pattern = /var/log/jenkins/jenkins-debug.log
java.util.logging.FileHandler.limit = 50000000
java.util.logging.FileHandler.count = 5
java.util.logging.FileHandler.formatter = java.util.logging.SimpleFormatter

# Component-specific logging
hudson.level = FINE
jenkins.level = FINE
hudson.security.level = FINE
hudson.plugins.level = FINE
hudson.model.level = FINE

# Plugin debugging
hudson.plugins.git.level = FINE
org.jenkinsci.plugins.workflow.level = FINE
EOF

sudo systemctl restart jenkins

# View debug logs
sudo tail -f /var/log/jenkins/jenkins-debug.log

# Enable specific plugin debugging via Jenkins CLI
java -jar jenkins-cli.jar -s http://localhost:8080 -auth admin:password groovy = <<EOF
import java.util.logging.Logger
import java.util.logging.Level

// Enable debug logging for specific components
Logger.getLogger("hudson.security").setLevel(Level.FINE)
Logger.getLogger("hudson.plugins.git").setLevel(Level.FINE)
Logger.getLogger("org.jenkinsci.plugins.workflow").setLevel(Level.FINE)

println "Debug logging enabled"
EOF
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo dnf check-update jenkins
sudo dnf update jenkins

# Debian/Ubuntu
sudo apt update
sudo apt upgrade jenkins

# Arch Linux
yay -Syu jenkins

# Alpine Linux (Docker)
docker pull jenkins/jenkins:lts-jdk17
docker stop jenkins
docker rm jenkins
# Re-run docker run command with new image

# openSUSE
sudo zypper update jenkins

# FreeBSD
pkg update
pkg upgrade jenkins

# macOS
brew upgrade jenkins-lts

# Always backup before updates
sudo /usr/local/bin/jenkins-backup.sh

# Update plugins after Jenkins update
java -jar jenkins-cli.jar -s http://localhost:8080 -auth admin:password list-plugins | grep -E "\)$" | awk '{print $1}' | xargs java -jar jenkins-cli.jar -s http://localhost:8080 -auth admin:password install-plugin

# Restart after updates
sudo systemctl restart jenkins
```

### Maintenance Tasks

```bash
#!/bin/bash
# jenkins-maintenance.sh

JENKINS_HOME="/var/lib/jenkins"
JENKINS_URL="http://localhost:8080"
ADMIN_CREDENTIALS="admin:SecureAdminPassword123!"

echo "🔧 Starting Jenkins maintenance tasks..."

# Clean up old builds
echo "🗑️  Cleaning up old builds..."
java -jar ${JENKINS_HOME}/jenkins-cli.jar -s ${JENKINS_URL} -auth ${ADMIN_CREDENTIALS} groovy = <<EOF
import jenkins.model.Jenkins
import hudson.model.*

Jenkins.instance.getAllItems(Job.class).each { job ->
    if (job.getBuilds().size() > 50) {
        def buildsToDelete = job.getBuilds().drop(50)
        println "Deleting \${buildsToDelete.size()} old builds for job: \${job.name}"
        buildsToDelete.each { build ->
            build.delete()
        }
    }
}
EOF

# Clean up workspace
echo "🧹 Cleaning up workspaces..."
java -jar ${JENKINS_HOME}/jenkins-cli.jar -s ${JENKINS_URL} -auth ${ADMIN_CREDENTIALS} groovy = <<EOF
import hudson.model.*
import hudson.FilePath
import jenkins.model.Jenkins

Jenkins.instance.getAllItems(AbstractProject.class).each { job ->
    def workspace = job.getWorkspace()
    if (workspace != null && workspace.exists()) {
        def size = workspace.length()
        if (size > 1024 * 1024 * 100) { // > 100MB
            println "Workspace for \${job.name} is \${size / (1024*1024)} MB"
            workspace.deleteRecursive()
            println "Cleaned workspace for job: \${job.name}"
        }
    }
}
EOF

# Update plugins
echo "🔌 Checking for plugin updates..."
java -jar ${JENKINS_HOME}/jenkins-cli.jar -s ${JENKINS_URL} -auth ${ADMIN_CREDENTIALS} list-plugins | grep -E "\)$" > /tmp/outdated-plugins.txt

if [ -s /tmp/outdated-plugins.txt ]; then
    echo "📦 Updating outdated plugins:"
    cat /tmp/outdated-plugins.txt
    
    # Update plugins
    awk '{print $1}' /tmp/outdated-plugins.txt | xargs java -jar ${JENKINS_HOME}/jenkins-cli.jar -s ${JENKINS_URL} -auth ${ADMIN_CREDENTIALS} install-plugin
    
    echo "🔄 Restarting Jenkins to apply plugin updates..."
    java -jar ${JENKINS_HOME}/jenkins-cli.jar -s ${JENKINS_URL} -auth ${ADMIN_CREDENTIALS} safe-restart
fi

# Clean up logs
echo "📋 Rotating and cleaning logs..."
find ${JENKINS_HOME}/logs -name "*.log" -mtime +7 -delete
find /var/log/jenkins -name "*.log.*" -mtime +7 -delete

# Disk usage check
echo "💾 Checking disk usage..."
DISK_USAGE=$(df ${JENKINS_HOME} | awk 'NR==2 {print $5}' | sed 's/%//')
if [ ${DISK_USAGE} -gt 80 ]; then
    echo "⚠️  High disk usage: ${DISK_USAGE}%"
    
    # Clean up large files
    find ${JENKINS_HOME}/jobs -name "*.log" -size +100M -mtime +3 -delete
    find ${JENKINS_HOME}/workspace -name "*" -size +500M -mtime +1 -delete
fi

# Backup verification
echo "🔍 Verifying recent backups..."
LATEST_BACKUP=$(ls -t /backup/jenkins/config/jenkins-home-*.tar.gz 2>/dev/null | head -1)
if [ -n "$LATEST_BACKUP" ]; then
    BACKUP_AGE=$(($(date +%s) - $(stat -c %Y "$LATEST_BACKUP")))
    if [ $BACKUP_AGE -gt 172800 ]; then  # 2 days
        echo "⚠️  Latest backup is older than 2 days: $LATEST_BACKUP"
        echo "💾 Running backup now..."
        /usr/local/bin/jenkins-backup.sh
    else
        echo "✅ Recent backup found: $LATEST_BACKUP"
    fi
else
    echo "❌ No backups found. Running backup..."
    /usr/local/bin/jenkins-backup.sh
fi

# Security check
echo "🔒 Running security checks..."
java -jar ${JENKINS_HOME}/jenkins-cli.jar -s ${JENKINS_URL} -auth ${ADMIN_CREDENTIALS} groovy = <<EOF
import jenkins.security.ApiTokenProperty
import hudson.security.SecurityRealm
import jenkins.model.Jenkins

def instance = Jenkins.getInstance()

// Check for default passwords
def realm = instance.getSecurityRealm()
if (realm instanceof hudson.security.HudsonPrivateSecurityRealm) {
    def users = realm.getAllUsers()
    users.each { user ->
        if (user.getId() == "admin") {
            println "⚠️  Default admin user found. Consider renaming or removing."
        }
    }
}

// Check for anonymous access
def authStrategy = instance.getAuthorizationStrategy()
if (authStrategy.hasPermission(org.acegisecurity.Authentication.ANONYMOUS_USER, Jenkins.READ)) {
    println "⚠️  Anonymous read access is enabled"
}

println "Security check completed"
EOF

# Performance check
echo "📊 Checking performance metrics..."
JAVA_PID=$(pgrep java)
if [ -n "$JAVA_PID" ]; then
    MEMORY_USAGE=$(ps -o pid,vsz,rss,comm -p $JAVA_PID | awk 'NR==2 {print $3/1024}')
    CPU_USAGE=$(ps -o pid,pcpu,comm -p $JAVA_PID | awk 'NR==2 {print $2}')
    
    echo "Memory usage: ${MEMORY_USAGE}MB"
    echo "CPU usage: ${CPU_USAGE}%"
    
    if (( $(echo "${MEMORY_USAGE} > 6144" | bc -l) )); then
        echo "⚠️  High memory usage detected"
    fi
fi

echo "✅ Jenkins maintenance completed"

# Generate maintenance report
cat > /var/log/jenkins-maintenance-$(date +%Y%m%d).log <<EOF
Jenkins Maintenance Report - $(date)
===================================

Tasks Completed:
- Old builds cleanup: ✅
- Workspace cleanup: ✅
- Plugin updates: $([ -s /tmp/outdated-plugins.txt ] && echo "✅ Updated" || echo "✅ Up to date")
- Log rotation: ✅
- Disk usage check: ✅ (${DISK_USAGE}%)
- Backup verification: ✅
- Security check: ✅
- Performance check: ✅

System Status:
- Memory usage: ${MEMORY_USAGE}MB
- CPU usage: ${CPU_USAGE}%
- Disk usage: ${DISK_USAGE}%

Next maintenance: $(date -d "next week" +%Y-%m-%d)
EOF

echo "📊 Maintenance report: /var/log/jenkins-maintenance-$(date +%Y%m%d).log"
```

### Health Monitoring

```bash
# Create monitoring cron job
echo "0 2 * * * root /usr/local/bin/jenkins-maintenance.sh" | sudo tee -a /etc/crontab
echo "*/15 * * * * root /usr/local/bin/jenkins-health-check.sh" | sudo tee -a /etc/crontab

# Log rotation configuration
sudo tee /etc/logrotate.d/jenkins <<EOF
/var/log/jenkins/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 jenkins adm
    postrotate
        systemctl reload jenkins > /dev/null 2>&1 || true
    endscript
}

/var/lib/jenkins/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 jenkins jenkins
}
EOF
```

## Integration Examples

### Git Integration with Webhooks

```bash
# Configure Git webhook for automatic builds
sudo tee /var/lib/jenkins/casc_configs/git-integration.yaml <<EOF
unclassified:
  gitHubPluginConfig:
    hookUrl: "https://jenkins.example.com/github-webhook/"
    
  gitLabConnectionConfig:
    connections:
      - name: "GitLab"
        url: "https://gitlab.example.com"
        apiTokenId: "gitlab-api-token"
        clientBuilderId: "autodetect"
        connectionTimeout: 10
        readTimeout: 10

jobs:
  - script: |
      multibranchPipelineJob('example-app') {
        branchSources {
          git {
            id('github-example')
            remote('https://github.com/example/app.git')
            credentialsId('github-credentials')
            includes('main develop feature/* release/*')
          }
        }
        
        factory {
          workflowBranchProjectFactory {
            scriptPath('Jenkinsfile')
          }
        }
        
        triggers {
          periodicFolderTrigger {
            interval('1d')
          }
        }
        
        orphanedItemStrategy {
          discardOldItems {
            daysToKeep(7)
            numToKeep(10)
          }
        }
      }
EOF
```

### Docker Integration

```groovy
// Docker pipeline example
pipeline {
    agent any
    
    environment {
        DOCKER_REGISTRY = credentials('docker-registry')
        DOCKER_IMAGE = "${env.JOB_NAME}:${env.BUILD_NUMBER}"
    }
    
    stages {
        stage('Build Docker Image') {
            steps {
                script {
                    def image = docker.build("${DOCKER_REGISTRY}/${DOCKER_IMAGE}")
                    
                    // Security scan
                    sh """
                        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
                            aquasec/trivy:latest image \
                            --severity HIGH,CRITICAL \
                            --exit-code 1 \
                            ${DOCKER_REGISTRY}/${DOCKER_IMAGE}
                    """
                    
                    // Push to registry
                    docker.withRegistry("https://${DOCKER_REGISTRY}", 'docker-registry-credentials') {
                        image.push()
                        image.push("latest")
                    }
                }
            }
        }
        
        stage('Deploy') {
            steps {
                script {
                    // Deploy to Kubernetes
                    sh """
                        kubectl set image deployment/myapp \
                            myapp=${DOCKER_REGISTRY}/${DOCKER_IMAGE} \
                            --namespace=production
                        
                        kubectl rollout status deployment/myapp \
                            --namespace=production --timeout=300s
                    """
                }
            }
        }
    }
}
```

### Kubernetes Integration

```yaml
# Jenkins agent in Kubernetes
apiVersion: v1
kind: ServiceAccount
metadata:
  name: jenkins
  namespace: jenkins
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: jenkins
rules:
- apiGroups: [""]
  resources: ["pods","pods/exec"]
  verbs: ["create","delete","get","list","patch","update","watch"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get","list","watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: jenkins
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: jenkins
subjects:
- kind: ServiceAccount
  name: jenkins
  namespace: jenkins
---
# Jenkins Configuration as Code for Kubernetes
jenkins:
  clouds:
    - kubernetes:
        name: "kubernetes"
        serverUrl: "https://kubernetes.default"
        namespace: "jenkins"
        credentialsId: "kubernetes-token"
        jenkinsUrl: "http://jenkins.jenkins.svc.cluster.local:8080"
        containerCapStr: "10"
        templates:
          - name: "jenkins-agent"
            namespace: "jenkins"
            label: "kubernetes"
            containers:
              - name: "jnlp"
                image: "jenkins/inbound-agent:latest"
                workingDir: "/home/jenkins/agent"
                resourceRequestCpu: "100m"
                resourceRequestMemory: "256Mi"
                resourceLimitCpu: "500m"
                resourceLimitMemory: "1Gi"
```

### LDAP/Active Directory Integration

```yaml
jenkins:
  securityRealm:
    ldap:
      configurations:
        - server: "ldaps://ad.example.com:636"
          rootDN: "DC=example,DC=com"
          inhibitInferRootDN: false
          userSearchBase: "OU=Users,OU=Company"
          userSearch: "(&(objectCategory=Person)(objectClass=user)(sAMAccountName={0}))"
          groupSearchBase: "OU=Groups,OU=Company"
          groupSearchFilter: "(&(objectClass=group)(cn={0}))"
          managerDN: "CN=jenkins,OU=Service Accounts,DC=example,DC=com"
          managerPasswordSecret: "ldap-service-password"
          displayNameAttributeName: "displayName"
          mailAddressAttributeName: "mail"
          
  authorizationStrategy:
    roleBased:
      roles:
        global:
          - name: "administrators"
            permissions:
              - "Overall/Administer"
            assignments:
              - "Domain Admins"
              - "Jenkins Admins"
        items:
          - name: "developers"
            pattern: ".*"
            permissions:
              - "Job/Build"
              - "Job/Cancel"
              - "Job/Read"
            assignments:
              - "Development Team"
```

## Additional Resources

- [Official Jenkins Documentation](https://www.jenkins.io/doc/)
- [Jenkins Configuration as Code](https://jenkins.io/projects/jcasc/)
- [Jenkins Pipeline Documentation](https://www.jenkins.io/doc/book/pipeline/)
- [Jenkins Security Guide](https://www.jenkins.io/doc/book/security/)
- [Jenkins Plugin Index](https://plugins.jenkins.io/)
- [Jenkins Community](https://www.jenkins.io/community/)
- [Jenkins Best Practices](https://www.jenkins.io/doc/book/pipeline/pipeline-best-practices/)
- [Jenkins GitHub Repository](https://github.com/jenkinsci/jenkins)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.