#!/usr/bin/env bash
# Bifrost — Tetragon Setup Script
# Installs Tetragon eBPF security observability
# and loads Bifrost tracing policies.
#
# Tetragon provides kernel-level syscall monitoring
# with near-zero overhead via eBPF.
#
# Usage: sudo bash setup.sh

set -e

POLICY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/policies"
TETRAGON_NAMESPACE="kube-system"

echo "╔══════════════════════════════════════════╗"
echo "║     BIFROST TETRAGON SETUP v0.1.0        ║"
echo "║     Kernel Layer Initialization          ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "[!] Run with sudo: sudo bash setup.sh"
    exit 1
fi

# Check if running standalone (no Kubernetes)
if ! command -v kubectl &> /dev/null; then
    echo "[*] Kubernetes not detected."
    echo "[*] Installing Tetragon in standalone mode..."

    # Install Tetragon binary directly
    if ! command -v tetragon &> /dev/null; then
        echo "[*] Downloading Tetragon..."
        TETRAGON_VERSION="v1.1.0"
        ARCH=$(uname -m)

        if [[ "$ARCH" == "x86_64" ]]; then
            ARCH="amd64"
        elif [[ "$ARCH" == "aarch64" ]]; then
            ARCH="arm64"
        fi

        wget -q -O /tmp/tetragon.tar.gz \
            "https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/tetragon-linux-${ARCH}.tar.gz"

        tar -xzf /tmp/tetragon.tar.gz -C /tmp/
        mv /tmp/tetragon /usr/local/bin/tetragon
        chmod +x /usr/local/bin/tetragon
        echo "[+] Tetragon installed."
    else
        echo "[+] Tetragon already installed."
    fi

    # Install tetra CLI tool
    if ! command -v tetra &> /dev/null; then
        wget -q -O /tmp/tetra.tar.gz \
            "https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/tetra-linux-${ARCH}.tar.gz"
        tar -xzf /tmp/tetra.tar.gz -C /tmp/
        mv /tmp/tetra /usr/local/bin/tetra
        chmod +x /usr/local/bin/tetra
        echo "[+] tetra CLI installed."
    fi

    # Create Tetragon config directory
    mkdir -p /etc/tetragon/tetragon.conf.d
    mkdir -p /var/log/tetragon

    # Write Tetragon config
    cat > /etc/tetragon/tetragon.conf.d/bifrost.conf << 'CONF'
export-filename=/var/log/tetragon/tetragon.log
export-file-max-size-mb=100
export-file-rotation-interval=24h
enable-process-ns=true
enable-process-cred=true
CONF

    # Copy policy files
    mkdir -p /etc/tetragon/tetragon.conf.d/policies
    cp "$POLICY_DIR"/*.yaml /etc/tetragon/tetragon.conf.d/policies/
    echo "[+] Tetragon policies installed."

    # Create systemd service for Tetragon
    cat > /etc/systemd/system/tetragon.service << 'SVCEOF'
[Unit]
Description=Tetragon eBPF Security Observability
After=network.target
Documentation=https://tetragon.io

[Service]
Type=simple
ExecStart=/usr/local/bin/tetragon \
    --config-dir=/etc/tetragon/tetragon.conf.d \
    --tracing-policy-dir=/etc/tetragon/tetragon.conf.d/policies
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tetragon

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable tetragon
    systemctl start tetragon
    echo "[+] Tetragon service started."

    # Set up log shipping to Bifrost Go agent
    cat > /etc/tetragon/tetragon.conf.d/bifrost-shipper.sh << 'SHIPPER'
#!/usr/bin/env bash
# Ships Tetragon events to Bifrost Go collector
# via Unix socket at /var/run/bifrost_telemetry.sock
tail -f /var/log/tetragon/tetragon.log | \
    while IFS= read -r line; do
        echo "$line" | socat - UNIX-CONNECT:/var/run/bifrost_telemetry.sock 2>/dev/null || true
    done
SHIPPER
    chmod +x /etc/tetragon/tetragon.conf.d/bifrost-shipper.sh

    # Create systemd service for log shipping
    cat > /etc/systemd/system/bifrost-tetragon-shipper.service << 'SHIPEOF'
[Unit]
Description=Bifrost Tetragon Log Shipper
After=tetragon.service bifrost-agent.service
Requires=tetragon.service

[Service]
Type=simple
ExecStart=/etc/tetragon/tetragon.conf.d/bifrost-shipper.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SHIPEOF

    systemctl daemon-reload
    systemctl enable bifrost-tetragon-shipper
    systemctl start bifrost-tetragon-shipper
    echo "[+] Tetragon log shipper started."

else
    echo "[*] Kubernetes detected. Installing via Helm..."

    if ! command -v helm &> /dev/null; then
        echo "[!] Helm not found. Install helm first."
        exit 1
    fi

    helm repo add cilium https://helm.cilium.io
    helm repo update

    helm install tetragon cilium/tetragon \
        --namespace "$TETRAGON_NAMESPACE" \
        --set tetragon.exportFilename=/var/log/tetragon/tetragon.log

    echo "[+] Tetragon installed via Helm."

    # Apply tracing policies
    for policy in "$POLICY_DIR"/*.yaml; do
        kubectl apply -f "$policy"
        echo "[+] Applied: $(basename $policy)"
    done
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║     TETRAGON SETUP COMPLETE              ║"
echo "║                                          ║"
echo "║  Kernel layer active.                    ║"
echo "║  Syscalls, filesystem, network watched.  ║"
echo "║                                          ║"
echo "║  Verify:                                 ║"
echo "║    sudo systemctl status tetragon        ║"
echo "║    sudo tetra getevents                  ║"
echo "║                                          ║"
echo "║  The bridge runs deeper now.             ║"
echo "╚══════════════════════════════════════════╝"
