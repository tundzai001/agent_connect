#!/usr/bin/env bash
set -euo pipefail

# Run this file from the cloned agent folder on the Raspberry Pi. The service
# runs that exact clone; device state is kept separately under /agent_connect.

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="agent_connect.service"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME"
SERVICE_USER="${AITOGY_SERVICE_USER:-${SUDO_USER:-$(id -un)}}"

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    SERVICE_USER="$(id -un)"
fi
SERVICE_GROUP="$(id -gn "$SERVICE_USER")"
AGENT_DIR="${AITOGY_CODE_DIR:-$SOURCE_DIR}"
STATE_DIR="${AITOGY_STATE_DIR:-/agent_connect}"
VENV_DIR="$AGENT_DIR/venv"

if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
    command -v apt-get >/dev/null 2>&1 || {
        echo "python3 and python3-venv are required." >&2
        exit 1
    }
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends python3 python3-venv ca-certificates
fi

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/python" -m pip install -r "$AGENT_DIR/requirements.txt"

sudo install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$STATE_DIR"
if [[ "$STATE_DIR" == "/agent_connect" && -d /var/lib/agent_connect ]] && \
   [[ ! -e "$STATE_DIR/device.token" && ! -e "$STATE_DIR/command.key" && ! -e "$STATE_DIR/agent.json" ]]; then
    echo "Migrating existing agent state from /var/lib/agent_connect to $STATE_DIR"
    sudo cp -a /var/lib/agent_connect/. "$STATE_DIR/"
fi
sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" "$STATE_DIR"
SERVICE_TMP="$(mktemp)"
trap 'rm -f "$SERVICE_TMP"' EXIT
cat > "$SERVICE_TMP" <<EOF
[Unit]
Description=Aitogy Linux edge agent
After=network-online.target
Wants=network-online.target

[Service]
User=$SERVICE_USER
Group=$SERVICE_GROUP
Environment=AITOGY_STATE_DIR=$STATE_DIR
WorkingDirectory=$AGENT_DIR
ExecStart=$VENV_DIR/bin/python $AGENT_DIR/agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
sudo install -m 0644 "$SERVICE_TMP" "$SERVICE_FILE"
rm -f "$SERVICE_TMP"
trap - EXIT

sudo systemctl daemon-reload
sudo systemctl disable --now edge-agent.service 2>/dev/null || true
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl restart "$SERVICE_NAME"

echo "Aitogy agent service is ready."
sudo systemctl --no-pager --full status "$SERVICE_NAME" || true
