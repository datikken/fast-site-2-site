#!/usr/bin/env bash
set -Eeuo pipefail

server_config=/etc/wireguard/wg0.conf
client_dir=/etc/wireguard/clients
interface=wg0

if [[ $EUID -ne 0 ]]; then
  printf 'Run this script as root: sudo bash %s\n' "$0" >&2
  exit 1
fi

for command_name in wg wg-quick flock awk; do
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

if [[ ! -d $client_dir || ! -r $client_dir ]]; then
  printf 'Cannot read client config directory: %s\n' "$client_dir" >&2
  exit 1
fi

if ! wg show "$interface" >/dev/null 2>&1; then
  printf 'WireGuard interface %s is not running. Start it before removing peers.\n' "$interface" >&2
  exit 1
fi

exec 9>/etc/wireguard/.peer-creation.lock
flock -x 9

shopt -s nullglob
client_configs=("$client_dir"/*.conf)
shopt -u nullglob
if (( ${#client_configs[@]} == 0 )); then
  printf 'No client configs found in %s; refusing to remove peers.\n' "$client_dir" >&2
  exit 1
fi

umask 077
temporary_config=$(mktemp --suffix=.conf /etc/wireguard/wg0cXXXXXX)
temporary_interface_config=${temporary_config##*/}
stripped_config=$(mktemp /etc/wireguard/.wg0.strip.XXXXXX)
peer_keys_file=
orphan_keys_file=
backup_config=
runtime_updated=false
committed=false
cleanup() {
  local exit_status=$?
  if [[ -n ${temporary_config:-} ]]; then
    rm -f -- "$temporary_config"
  fi
  if [[ -n ${stripped_config:-} ]]; then
    rm -f -- "$stripped_config"
  fi
  if [[ -n ${peer_keys_file:-} ]]; then
    rm -f -- "$peer_keys_file"
  fi
  if [[ -n ${orphan_keys_file:-} ]]; then
    rm -f -- "$orphan_keys_file"
  fi
  if [[ $runtime_updated == true && $committed != true ]]; then
    if wg-quick strip "$interface" > "$stripped_config" &&
      wg syncconf "$interface" "$stripped_config"; then
      printf 'Restored the running interface from the unchanged server config.\n' >&2
    else
      printf 'Could not restore the running interface; inspect %s and wg0 immediately.\n' "$server_config" >&2
    fi
  fi
  exit "$exit_status"
}
trap cleanup EXIT

declare -A managed_public_keys=()
for client_config in "${client_configs[@]}"; do
  if [[ ! -f $client_config || ! -r $client_config ]]; then
    printf 'Cannot read client config: %s\n' "$client_config" >&2
    exit 1
  fi

  client_private_key=$(awk '
    /^\[[^]]+\][[:space:]]*$/ {
      in_interface = ($0 ~ /^[[:space:]]*\[Interface\][[:space:]]*$/)
      next
    }
    in_interface && /^[[:space:]]*PrivateKey[[:space:]]*=/ {
      value = $0
      sub(/^[[:space:]]*PrivateKey[[:space:]]*=/, "", value)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      key_count++
      private_key = value
    }
    END {
      if (key_count != 1 || private_key == "") {
        exit 1
      }
      print private_key
    }
  ' "$client_config") || {
    printf 'Expected exactly one interface PrivateKey in %s; refusing to remove peers.\n' "$client_config" >&2
    exit 1
  }

  if ! client_public_key=$(printf '%s\n' "$client_private_key" | wg pubkey); then
    printf 'Could not derive a public key from %s; refusing to remove peers.\n' "$client_config" >&2
    exit 1
  fi
  managed_public_keys["$client_public_key"]=1
done

peer_keys_file=$(mktemp /etc/wireguard/.wg0.peers.XXXXXX)
orphan_keys_file=$(mktemp /etc/wireguard/.wg0.orphans.XXXXXX)

if ! awk '
  function finish_peer() {
    if (in_peer && key_count != 1) {
      printf "A [Peer] section must contain exactly one PublicKey (near line %d).\n", peer_start > "/dev/stderr"
      failed = 1
    }
  }
  {
    line = $0
    trimmed = line
    sub(/^[[:space:]]+/, "", trimmed)
    if (trimmed ~ /^\[[^]]+\][[:space:]]*$/) {
      finish_peer()
      in_peer = (trimmed ~ /^\[Peer\][[:space:]]*$/)
      key_count = 0
      peer_start = NR
      next
    }
    if (in_peer && trimmed ~ /^PublicKey[[:space:]]*=/) {
      value = trimmed
      sub(/^PublicKey[[:space:]]*=/, "", value)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      key_count++
      if (key_count == 1 && value != "") {
        print value
      } else {
        failed = 1
      }
    }
  }
  END {
    finish_peer()
    if (failed) {
      exit 1
    }
  }
' "$server_config" > "$peer_keys_file"; then
  printf 'Could not safely parse peer sections in %s; no peers were changed.\n' "$server_config" >&2
  exit 1
fi

orphan_count=0
while IFS= read -r peer_public_key; do
  if [[ -z ${managed_public_keys[$peer_public_key]+x} ]]; then
    printf '%s\n' "$peer_public_key" >> "$orphan_keys_file"
    ((orphan_count += 1))
  fi
done < "$peer_keys_file"

if [[ ! -s $orphan_keys_file ]]; then
  printf 'No orphan peers found in %s; nothing to remove.\n' "$server_config"
  exit 0
fi

if ! awk -v orphan_file="$orphan_keys_file" '
  BEGIN {
    while ((getline key < orphan_file) > 0) {
      orphan[key] = 1
    }
    close(orphan_file)
  }
  {
    lines[NR] = $0
    trimmed = $0
    sub(/^[[:space:]]+/, "", trimmed)
    if (trimmed ~ /^\[[^]]+\][[:space:]]*$/) {
      if (in_peer) {
        peer_end[peer_count] = NR - 1
      }
      in_peer = (trimmed ~ /^\[Peer\][[:space:]]*$/)
      if (in_peer) {
        peer_count++
        peer_start[peer_count] = NR
        peer_key[peer_count] = ""
      }
      next
    }
    if (in_peer && trimmed ~ /^PublicKey[[:space:]]*=/) {
      value = trimmed
      sub(/^PublicKey[[:space:]]*=/, "", value)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      peer_key[peer_count] = value
    }
  }
  END {
    if (in_peer) {
      peer_end[peer_count] = NR
    }
    for (peer = 1; peer <= peer_count; peer++) {
      if (peer_key[peer] in orphan) {
        for (line = peer_start[peer]; line <= peer_end[peer]; line++) {
          skip[line] = 1
        }
        preceding = peer_start[peer] - 1
        if (preceding > 0 && lines[preceding] ~ /^[[:space:]]*#[[:space:]]*Client:[[:space:]]*/) {
          skip[preceding] = 1
        }
        removed++
      }
    }
    if (removed == 0) {
      print "No matching peer sections were found for the orphan keys." > "/dev/stderr"
      exit 1
    }
    for (line = 1; line <= NR; line++) {
      if (!skip[line]) {
        print lines[line]
      }
    }
  }
' "$server_config" > "$temporary_config"; then
  printf 'Could not safely prepare the updated server config; no peers were changed.\n' >&2
  exit 1
fi

chmod 600 "$temporary_config"
backup_config=$(mktemp /etc/wireguard/wg0.conf.backup.XXXXXX)
cp -p "$server_config" "$backup_config"

if ! wg-quick strip "$temporary_interface_config" > "$stripped_config"; then
  printf 'Could not prepare the updated running WireGuard config; no peers were changed.\n' >&2
  exit 1
fi
if ! wg syncconf "$interface" "$stripped_config"; then
  printf 'Could not apply the peer removals to the running interface; config file was not changed.\n' >&2
  exit 1
fi
runtime_updated=true

if ! mv -f -- "$temporary_config" "$server_config"; then
  printf 'Could not save the updated server config. The old config backup is at %s.\n' "$backup_config" >&2
  exit 1
fi
temporary_config=
committed=true

printf 'Removed %s peer(s) without matching client configs.\n' "$orphan_count"
printf 'Updated server config: %s\n' "$server_config"
printf 'Backup of the previous config: %s\n' "$backup_config"
