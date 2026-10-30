#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $EUID -ne 0 ]]; then
  printf 'Run this script as root: sudo bash %s\n' "$0" >&2
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  printf 'Cannot identify this Linux distribution (missing /etc/os-release).\n' >&2
  exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release
if [[ ${ID:-} != debian && ${ID:-} != ubuntu ]]; then
  printf 'This script supports Debian and Ubuntu only (detected: %s).\n' "${ID:-unknown}" >&2
  exit 1
fi

if [[ -f /etc/wireguard/wg0.conf ]]; then
  printf 'An existing /etc/wireguard/wg0.conf was found; refusing to overwrite it.\n' >&2
  exit 1
fi

if ! command -v ip >/dev/null 2>&1; then
  printf 'The ip command is required. Install iproute2 and run this script again.\n' >&2
  exit 1
fi

wan_interface=$(ip -o -4 route show default | awk 'NR == 1 { print $5; exit }')
if [[ -z $wan_interface || ! $wan_interface =~ ^[[:alnum:]_.:-]+$ ]]; then
  printf 'Could not determine a valid default IPv4 network interface.\n' >&2
  exit 1
fi

detected_endpoint=
if command -v curl >/dev/null 2>&1; then
  detected_endpoint=$(curl -4fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)
fi

read -r -p "Server public IPv4 address or DNS name${detected_endpoint:+ [$detected_endpoint]}: " endpoint
endpoint=${endpoint:-$detected_endpoint}
if [[ ! $endpoint =~ ^[A-Za-z0-9.-]+$ || $endpoint == .* || $endpoint == *. || $endpoint == *..* ]]; then
  printf 'Enter a public IPv4 address or DNS name (without a port).\n' >&2
  exit 1
fi

read -r -p 'WireGuard UDP port [51820]: ' listen_port
listen_port=${listen_port:-51820}
if [[ ! $listen_port =~ ^[0-9]{1,5}$ ]] || (( 10#$listen_port < 1 || 10#$listen_port > 65535 )); then
  printf 'The port must be a number from 1 to 65535.\n' >&2
  exit 1
fi

read -r -p 'Client name [client1]: ' client_name
client_name=${client_name:-client1}
if [[ ! $client_name =~ ^[A-Za-z0-9_-]+$ ]]; then
  printf 'Use only letters, numbers, underscores, and hyphens for the client name.\n' >&2
  exit 1
fi

client_dir="/etc/wireguard/clients"
client_config="$client_dir/$client_name.conf"
if [[ -e $client_config ]]; then
  printf 'Client config already exists: %s\n' "$client_config" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y wireguard iptables curl

install -d -m 700 /etc/wireguard "$client_dir"
umask 077

server_private_key=$(wg genkey)
server_public_key=$(printf '%s' "$server_private_key" | wg pubkey)
client_private_key=$(wg genkey)
client_public_key=$(printf '%s' "$client_private_key" | wg pubkey)

cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.8.0.1/24
ListenPort = $listen_port
PrivateKey = $server_private_key
SaveConfig = false
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $wan_interface -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $wan_interface -j MASQUERADE

[Peer]
PublicKey = $client_public_key
AllowedIPs = 10.8.0.2/32
EOF
chmod 600 /etc/wireguard/wg0.conf

cat > "$client_config" <<EOF
[Interface]
PrivateKey = $client_private_key
Address = 10.8.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = $server_public_key
Endpoint = $endpoint:$listen_port
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
chmod 600 "$client_config"

cat > /etc/sysctl.d/99-wireguard-forward.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
sysctl --system

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  ufw allow "$listen_port/udp"
fi

systemctl enable --now wg-quick@wg0

printf '\nWireGuard server is installed and wg0 is enabled.\n'
printf 'Allow UDP port %s in your VDS provider firewall/security group if one is enabled.\n' "$listen_port"
printf 'Client configuration (keep private): %s\n' "$client_config"
printf 'Transfer this config to the client securely, then import it in the WireGuard app.\n'
