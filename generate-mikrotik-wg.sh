#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Использование: $0 /путь/к/wg.conf" >&2
    exit 1
fi

CONF="$1"

if [[ ! -f "$CONF" ]]; then
    echo "Файл не найден: $CONF" >&2
    exit 1
fi

# Извлекаем значения из конфига (простые grep/sed, без сложного парсинга)
PRIVATE_KEY=$(grep '^PrivateKey' "$CONF" | head -n1 | sed 's/^[^=]*=\s*//')
ADDRESS=$(grep '^Address' "$CONF" | head -n1 | sed 's/^[^=]*=\s*//')
DNS=$(grep '^DNS' "$CONF" | head -n1 | sed 's/^[^=]*=\s*//')

PUBLIC_KEY=$(grep '^PublicKey' "$CONF" | grep -v 'Interface' | head -n1 | sed 's/^[^=]*=\s*//')
ENDPOINT=$(grep '^Endpoint' "$CONF" | head -n1 | sed 's/^[^=]*=\s*//')
ALLOWED_IPS=$(grep '^AllowedIPs' "$CONF" | head -n1 | sed 's/^[^=]*=\s*//')
PERSISTENT_KEEPALIVE=$(grep '^PersistentKeepalive' "$CONF" | head -n1 | sed 's/^[^=]*=\s*//')

# Разбираем IP/маску для интерфейса
IFACE_IP=$(echo "$ADDRESS" | cut -d/ -f1)
IFACE_MASK=$(echo "$ADDRESS" | cut -d/ -f2)

# Получаем IP и порт из Endpoint
WG_HOST=$(echo "$ENDPOINT" | cut -d: -f1)
WG_PORT=$(echo "$ENDPOINT" | cut -d: -f2)

echo "# --- Команды для MikroTik (RouterOS) ---"
echo ""
echo "# 1. Создаем WireGuard интерфейс"
echo "/interface wireguard add name=wg0 listen-port=51820 private-key=\"$PRIVATE_KEY\""
echo ""
echo "# 2. Назначаем IP на интерфейс"
echo "/ip address add interface=wg0 address=\"$IFACE_IP/$IFACE_MASK\""

if [[ -n "$DNS" ]]; then
  echo ""
  echo "# 3. (Опционально) DNS (на MikroTik лучше ставить в DHCP Client или в IP DNS, но можно и здесь для справки)"
  echo "# Примечание: в RouterOS DNS не задаётся на интерфейсе напрямую. Используйте IP DNS или DHCP Client."
fi

echo ""
echo "# 4. Добавляем пир (Peer)"
echo "/interface wireguard peers add interface=wg0 public-key=\"$PUBLIC_KEY\" endpoint-address=\"$WG_HOST\" endpoint-port=\"$WG_PORT\" allowed-address=\"$ALLOWED_IPS\""

if [[ -n "$PERSISTENT_KEEPALIVE" ]]; then
  echo "/interface wireguard peers set [find interface=wg0] persistent-keepalive=$PERSISTENT_KEEPALIVE"
fi

echo ""
echo "# 5. Разрешаем трафик (NAT для выхода в интернет через WG)"
echo "# Если MikroTik должен маршрутизировать трафик через WG (как клиент), нужен srcnat:"
echo "/ip firewall nat add chain=srcnat out-interface=wg0 action=masquerade"
echo ""
echo "# 6. (Опционально) Маршрут по умолчанию через WG, если это клиентское подключение:"
echo "# /ip route add dst-address=0.0.0.0/0 gateway=wg0 distance=1"
