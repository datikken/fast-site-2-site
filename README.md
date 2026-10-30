## To set up wireguard
```bash
bash deploy-wireguard.sh
```

### To add a new peer and create a configuration file in `/etc/wireguard/clients`
```bash
sudo bash add-wireguard-peer.sh colleague-name
```

### To remove peers without a matching client config
```bash
sudo bash remove-stale-wireguard-peers.sh
```

The cleanup script matches each server peer's public key against public keys
derived from the private keys in `/etc/wireguard/clients/*.conf`. It backs up
`wg0.conf` before removing unmatched peers and synchronizes the running `wg0`
interface.