#!/usr/bin/env bash
set -Eeuo pipefail

server_config=/etc/wireguard/wg0.conf
client_dir=/etc/wireguard/clients
interface=wg0

if [[ $EUID -ne 0 ]]; then
  printf 'Run this script as root: sudo bash %s [client-name]\n' "$0" >&2
  exit 1
fi

if (( $# > 1 )); then
  printf 'Usage: sudo bash %s [client-name]\n' "$0" >&2
  exit 1
fi

for command_name in wg flock awk; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'The %s command is required.\n' "$command_name" >&2
    exit 1
  fi
done

if [[ ! -f $server_config ]]; then
  printf 'No existing WireGuard server config found at %s. Run deploy-wireguard.sh first.\n' "$server_config" >&2
  exit 1
fi

if [[ ! -r $server_config ]]; then
  printf 'Cannot read existing WireGuard server config: %s\n' "$server_config" >&2
  exit 1
fi

if ! wg show "$interface" >/dev/null 2>&1; then
  printf 'WireGuard interface %s is not running. Start it before adding a peer.\n' "$interface" >&2
  exit 1
fi

exec 9>/etc/wireguard/.peer-creation.lock
flock -x 9

client_name=${1:-}
if [[ -z $client_name ]]; then
  read -r -p 'Client name: ' client_name
fi
if [[ ! $client_name =~ ^[A-Za-z0-9_-]+$ ]]; then
  printf 'Use only letters, numbers, underscores, and hyphens for the client name.\n' >&2
  exit 1
fi

client_config="$client_dir/$client_name.conf"
if [[ -e $client_config ]]; then
  printf 'Client config already exists: %s\n' "$client_config" >&2
  exit 1
fi

server_address=$(awk -F= '
  /^[[:space:]]*Address[[:space:]]*=/ {
    gsub(/[[:space:]]/, "", $2)
    if ($2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/24$/) {
      print $2
      exit
    }
  }
' "$server_config")
listen_port=$(awk -F= '
  /^[[:space:]]*ListenPort[[:space:]]*=/ {
    gsub(/[[:space:]]/, "", $2)
    if ($2 ~ /^[0-9]+$/) {
      print $2
      exit
    }
  }
' "$server_config")

if [[ -z $server_address || ! $listen_port =~ ^[0-9]{1,5}$ ]] || (( 10#$listen_port < 1 || 10#$listen_port > 65535 )); then
  printf 'Could not read a valid IPv4 /24 address and listen port from %s.\n' "$server_config" >&2
  exit 1
fi

server_public_key=$(wg show "$interface" public-key)
if [[ -z $server_public_key ]]; then
  printf 'Could not read the public key for interface %s.\n' "$interface" >&2
  exit 1
fi

is_valid_endpoint() {
  local value=$1
  local label
  local octet
  local -a labels

  if [[ $value =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    IFS='.' read -r -a labels <<< "$value"
    for octet in "${labels[@]}"; do
      (( 10#$octet <= 255 )) || return 1
    done
    return 0
  fi

  [[ ${#value} -le 253 && $value =~ ^[A-Za-z0-9.-]+$ ]] || return 1
  [[ $value != .* && $value != *..* && $value != *. ]] || return 1

  IFS='.' read -r -a labels <<< "$value"
  for label in "${labels[@]}"; do
    [[ ${#label} -le 63 && $label =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
  done
}

endpoint=
shopt -s nullglob
existing_client_configs=("$client_dir"/*.conf)
shopt -u nullglob
if (( ${#existing_client_configs[@]} == 0 )); then
  printf 'No existing client config was found in %s to read the server endpoint from.\n' "$client_dir" >&2
  exit 1
fi

for existing_config in "${existing_client_configs[@]}"; do
  configured_endpoint=$(awk -F= '
    /^\[[^]]+\][[:space:]]*$/ {
      in_peer = ($0 ~ /^[[:space:]]*\[Peer\][[:space:]]*$/)
      next
    }
    in_peer && /^[[:space:]]*Endpoint[[:space:]]*=/ {
      sub(/^[^=]*=/, "")
      gsub(/^[[:space:]]+|[[:space:]]+$/, "")
      print
      exit
    }
  ' "$existing_config")
  [[ -n $configured_endpoint ]] || continue

  configured_port=${configured_endpoint##*:}
  configured_host=${configured_endpoint%:*}
  if [[ $configured_endpoint != *:* || ! $configured_port =~ ^[0-9]{1,5}$ ]] || (( 10#$configured_port != 10#$listen_port )); then
    printf 'Invalid or mismatched server endpoint in %s (expected UDP port %s).\n' "$existing_config" "$listen_port" >&2
    exit 1
  fi
  if ! is_valid_endpoint "$configured_host"; then
    printf 'Invalid server endpoint in %s.\n' "$existing_config" >&2
    exit 1
  fi
  if [[ -n $endpoint && $endpoint != "$configured_host" ]]; then
    printf 'Existing client configs contain different server endpoints; update them to match before adding a peer.\n' >&2
    exit 1
  fi
  endpoint=$configured_host
done

if [[ -z $endpoint ]]; then
  printf 'Could not find a server Endpoint in existing client configs under %s.\n' "$client_dir" >&2
  exit 1
fi

IFS='/' read -r server_ip _ <<< "$server_address"
IFS='.' read -r -a server_octets <<< "$server_ip"
if (( ${#server_octets[@]} != 4 )); then
  printf 'Invalid server IPv4 address in %s.\n' "$server_config" >&2
  exit 1
fi
for octet in "${server_octets[@]}"; do
  if (( 10#$octet > 255 )); then
    printf 'Invalid server IPv4 address in %s.\n' "$server_config" >&2
    exit 1
  fi
done
client_prefix="${server_octets[0]}.${server_octets[1]}.${server_octets[2]}"

used_ips=$(
  {
    awk -F= '
      /^[[:space:]]*AllowedIPs[[:space:]]*=/ {
        gsub(/[[:space:]]/, "", $2)
        count = split($2, entries, ",")
        for (i = 1; i <= count; i++) {
          if (entries[i] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/) {
            sub(/\/[0-9]+$/, "", entries[i])
            print entries[i]
          }
        }
      }
    ' "$server_config"
    wg show "$interface" allowed-ips | awk '
      {
        count = split($2, entries, ",")
        for (i = 1; i <= count; i++) {
          if (entries[i] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/) {
            sub(/\/[0-9]+$/, "", entries[i])
            print entries[i]
          }
        }
      }
    '
  }
)

declare -A used_addresses=()
while IFS= read -r used_ip; do
  if [[ -n $used_ip ]]; then
    used_addresses["$used_ip"]=1
  fi
done <<< "$used_ips"
used_addresses["$server_ip"]=1

client_ip=
for last_octet in {1..254}; do
  candidate_ip="$client_prefix.$last_octet"
  if [[ -z ${used_addresses[$candidate_ip]+x} ]]; then
    client_ip=$candidate_ip
    break
  fi
done

if [[ -z $client_ip ]]; then
  printf 'No unused IPv4 address remains in %s/24.\n' "$client_prefix" >&2
  exit 1
fi

install -d -m 700 "$client_dir"
umask 077
client_private_key=$(wg genkey)
client_public_key=$(printf '%s' "$client_private_key" | wg pubkey)

temporary_config=$(mktemp /etc/wireguard/.wg0.conf.XXXXXX)
peer_added=false
client_config_created=false
committed=false
cleanup() {
  local exit_status=$?
  if [[ -n ${temporary_config:-} ]]; then
    rm -f -- "$temporary_config"
  fi
  if [[ $client_config_created == true && $committed != true ]]; then
    rm -f -- "$client_config"
  fi
  if [[ $peer_added == true && $committed != true ]]; then
    wg set "$interface" peer "$client_public_key" remove || {
      printf 'Failed to remove the uncommitted peer from %s.\n' "$interface" >&2
    }
  fi
  exit "$exit_status"
}
trap cleanup EXIT

cp -p "$server_config" "$temporary_config"
cat >> "$temporary_config" <<EOF

[Peer]
PublicKey = $client_public_key
AllowedIPs = $client_ip/32
EOF
chmod 600 "$temporary_config"

client_config_created=true
cat > "$client_config" <<EOF
[Interface]
PrivateKey = $client_private_key
Address = $client_ip/24
DNS = 1.1.1.1

[Peer]
PublicKey = $server_public_key
Endpoint = $endpoint:$listen_port
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
chmod 600 "$client_config"

if ! wg set "$interface" peer "$client_public_key" allowed-ips "$client_ip/32"; then
  printf 'Could not activate the new peer on %s.\n' "$interface" >&2
  exit 1
fi
peer_added=true
if ! mv -f -- "$temporary_config" "$server_config"; then
  printf 'Could not save the peer to %s.\n' "$server_config" >&2
  exit 1
fi
temporary_config=
committed=true

printf '\nAdded peer %s with tunnel address %s.\n' "$client_name" "$client_ip"
printf 'Client configuration: %s\n' "$client_config"
printf 'Transfer that file securely; it contains the client private key.\n'
