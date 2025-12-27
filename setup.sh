#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This setup script only supports Linux." >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'USAGE'
Usage: ./setup.sh [--uninstall]

Options:
  --uninstall  Remove the puffproxy service, binary, and systemd unit.
USAGE
}

if [[ ! -f "${ROOT_DIR}/go.mod" ]]; then
  echo "Run this script from the repository root." >&2
  exit 1
fi

ACTION="install"
if [[ $# -gt 0 ]]; then
  case "${1}" in
    --uninstall|uninstall)
      ACTION="uninstall"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: ${1}" >&2
      usage >&2
      exit 1
      ;;
  esac
fi

SUDO=""
if [[ $(id -u) -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    echo "sudo is required to install dependencies and configure the service." >&2
    exit 1
  fi
fi

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

uninstall() {
  if have_cmd systemctl; then
    $SUDO systemctl disable --now puffproxy >/dev/null 2>&1 || true
  fi

  if [[ -f /etc/systemd/system/puffproxy.service ]]; then
    $SUDO rm -f /etc/systemd/system/puffproxy.service
    if have_cmd systemctl; then
      $SUDO systemctl daemon-reload
    fi
  fi

  $SUDO rm -f /usr/local/bin/puffproxy

  echo "PeaPufferProxy (puffproxy) is uninstalled. Data in /opt/puffproxy was left intact."
}

install_packages() {
  local packages=(curl ca-certificates git)

  if have_cmd apt-get; then
    $SUDO apt-get update
    $SUDO apt-get install -y --no-install-recommends "${packages[@]}" build-essential golang
  elif have_cmd dnf; then
    $SUDO dnf install -y "${packages[@]}" gcc make golang
  elif have_cmd yum; then
    $SUDO yum install -y "${packages[@]}" gcc make golang
  elif have_cmd pacman; then
    $SUDO pacman -Sy --noconfirm "${packages[@]}" base-devel go
  elif have_cmd zypper; then
    $SUDO zypper install -y "${packages[@]}" gcc make go
  elif have_cmd apk; then
    $SUDO apk add --no-cache "${packages[@]}" build-base go
  else
    echo "Unsupported package manager. Install Go, curl, and git manually." >&2
    exit 1
  fi
}

if [[ "${ACTION}" == "uninstall" ]]; then
  uninstall
  exit 0
fi

if ! have_cmd go; then
  echo "Go not found. Installing dependencies..."
  install_packages
fi

if ! have_cmd go; then
  echo "Go is still missing after installation." >&2
  exit 1
fi

$SUDO install -d -m 0755 /usr/local/bin

cd "${ROOT_DIR}"

go build -o /tmp/puffproxy
$SUDO install -m 0755 /tmp/puffproxy /usr/local/bin/puffproxy
rm -f /tmp/puffproxy

SERVICE_USER="root"
SERVICE_HOME="/opt/puffproxy"

$SUDO install -d -m 0755 "${SERVICE_HOME}"
$SUDO install -d -m 0755 "${SERVICE_HOME}/certs"
$SUDO chown "${SERVICE_USER}:${SERVICE_USER}" "${SERVICE_HOME}"
$SUDO chown "${SERVICE_USER}:${SERVICE_USER}" "${SERVICE_HOME}/certs"

CONFIG_FILE="${SERVICE_HOME}/proxy_config.json"
if [[ ! -f "${CONFIG_FILE}" ]]; then
  cat <<'JSON' | $SUDO tee "${CONFIG_FILE}" >/dev/null
{
  "hosts": {},
  "certs": {},
  "users": {}
}
JSON
fi
$SUDO chown "${SERVICE_USER}:${SERVICE_USER}" "${CONFIG_FILE}"

echo "Checking for configuration upgrades..."
$SUDO /usr/local/bin/puffproxy --upgrade-config

ADMIN_FILE="${SERVICE_HOME}/.admin_credentials"
if [[ ! -f "${ADMIN_FILE}" ]]; then
  $SUDO touch "${ADMIN_FILE}"
fi
$SUDO chmod 0600 "${ADMIN_FILE}"
$SUDO chown "${SERVICE_USER}:${SERVICE_USER}" "${ADMIN_FILE}"

SERVICE_FILE="/etc/systemd/system/puffproxy.service"
cat <<SERVICE | $SUDO tee "${SERVICE_FILE}" >/dev/null
[Unit]
Description=PeaPufferProxy (puffproxy)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${SERVICE_HOME}
ExecStart=/usr/local/bin/puffproxy
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
SERVICE

if have_cmd systemctl; then
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now puffproxy
  echo "PeaPufferProxy (puffproxy) is installed and running."
else
  echo "Systemd is not available. Run /usr/local/bin/puffproxy manually." >&2
fi
