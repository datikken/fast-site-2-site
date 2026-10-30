## To set up wireguard
```bash
bash deploy-wireguard.sh
```

### To add a new peer and create a configuration file in `/etc/wireguard/clients`
```bash
sudo bash add-wireguard-peer.sh colleague-name
```

### To generate MikroTik RouterOS v7 WireGuard commands
```bash
bash generate-routeros-wireguard-commands.sh /etc/wireguard/clients/colleague-name.conf
```

The script prints commands for the WireGuard interface, client address, and
server peer; it does not apply them. Review and paste the output into RouterOS.
The output contains the client's private key. DNS and IP routing are not changed.