#!/usr/bin/env python3
"""Deploy the CRSF2 routed OpenVPN hub for MikroTik A, MikroTik B, and Windows."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path


OPENVPN_DIR = Path("/etc/openvpn")
SERVER_DIR = OPENVPN_DIR / "server"
PKI_DIR = OPENVPN_DIR / "easy-rsa" / "pki"
SYSCTL_FILE = Path("/etc/sysctl.d/90-openvpn-forwarding.conf")
CLIENT_OUTPUT = Path("/root/openvpn-clients")
EASYRSA = Path("/usr/share/easy-rsa/easyrsa")
DEFAULT_TUNNEL = ipaddress.ip_network("10.77.0.0/24")
WINDOWS_CLIENT = ("windows-client", "10.77.0.4")
WINDOWS_LAN = ipaddress.ip_network("192.168.11.0/24")
CLIENTS = (
    ("mikrotik-a", "192.168.66.0/24", "192.168.55.0/24", "10.77.0.2"),
    ("mikrotik-b", "192.168.55.0/24", "192.168.66.0/24", "10.77.0.3"),
)


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, check=True, env=env)


def atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(content)
        temporary_path.chmod(mode)
        temporary_path.replace(path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def prompt_network(label: str, default: str) -> ipaddress.IPv4Network:
    while True:
        value = input(f"{label} [{default}]: ").strip() or default
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError:
            print("Enter a valid IPv4 network in CIDR notation, e.g. 192.168.66.0/24.")
            continue
        if not isinstance(network, ipaddress.IPv4Network):
            print("Only IPv4 networks are supported.")
            continue
        return network


def prompt_endpoint() -> str:
    while True:
        value = input("VDS public IPv4 or DNS name: ").strip()
        if not value or any(char.isspace() for char in value) or any(
            char in value for char in ('"', "'", ";", "\\")
        ):
            print("Enter a public IPv4 address or DNS name.")
            continue
        try:
            address = ipaddress.ip_address(value)
            if not isinstance(address, ipaddress.IPv4Address):
                print("This server configuration uses UDP/IPv4; enter an IPv4 address or DNS name.")
                continue
        except ValueError:
            if not all(
                label and len(label) <= 63 and label[0] != "-" and label[-1] != "-"
                and all(char.isalnum() or char == "-" for char in label)
                for label in value.rstrip(".").split(".")
            ):
                print("Enter a public IPv4 address or DNS name.")
                continue
        return value


def prompt_port() -> int:
    while True:
        value = input("OpenVPN UDP port [1194]: ").strip() or "1194"
        try:
            port = int(value)
        except ValueError:
            port = 0
        if 1 <= port <= 65535:
            return port
        print("Enter a port between 1 and 65535.")


def ensure_ubuntu() -> None:
    if not Path("/etc/os-release").exists():
        fail("This script supports Ubuntu only.")
    release = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            release[key] = value.strip('"')
    if release.get("ID") != "ubuntu":
        fail("This script supports Ubuntu only.")


def easyrsa(*arguments: str, common_name: str | None = None) -> None:
    env = os.environ.copy()
    env.update({"EASYRSA_BATCH": "1", "EASYRSA_PKI": str(PKI_DIR)})
    if common_name:
        env["EASYRSA_REQ_CN"] = common_name
    run([str(EASYRSA), *arguments], env=env)


def issue_certificate(name: str, cert_type: str) -> None:
    certificate = PKI_DIR / "issued" / f"{name}.crt"
    private_key = PKI_DIR / "private" / f"{name}.key"
    if certificate.exists() and private_key.exists():
        return
    if certificate.exists() or private_key.exists():
        fail(f"Incomplete existing certificate for {name}; inspect {PKI_DIR} before continuing.")
    easyrsa(
        "build-server-full" if cert_type == "server" else "build-client-full",
        name,
        "nopass",
    )


def write_backup(path: Path, timestamp: str) -> None:
    if path.exists():
        backup = path.with_name(f"{path.name}.bak.{timestamp}")
        shutil.copy2(path, backup)
        print(f"Backed up {path} to {backup}")


def select_openvpn_service() -> tuple[str, Path]:
    services = (
        ("openvpn-server@.service", "openvpn-server@server.service", SERVER_DIR / "server.conf"),
        ("openvpn@.service", "openvpn@server.service", OPENVPN_DIR / "server.conf"),
    )
    for template, instance, config in services:
        result = subprocess.run(
            ["systemctl", "cat", template], capture_output=True, text=True
        )
        if result.returncode == 0:
            return instance, config
    fail("Could not find an OpenVPN systemd service template.")


def restart_openvpn_service(service: str) -> None:
    result = subprocess.run(
        ["systemctl", "restart", service], capture_output=True, text=True
    )
    if result.returncode == 0:
        return

    print(f"ERROR: systemctl restart {service} failed.", file=sys.stderr)
    if result.stdout.strip():
        print(result.stdout.strip(), file=sys.stderr)
    if result.stderr.strip():
        print(result.stderr.strip(), file=sys.stderr)
    for command in (
        ["systemctl", "status", "--no-pager", "--full", service],
        ["journalctl", "-u", service, "-n", "40", "--no-pager"],
    ):
        diagnostic = subprocess.run(command, capture_output=True, text=True)
        output = diagnostic.stdout.strip() or diagnostic.stderr.strip()
        if output:
            print(output, file=sys.stderr)
    raise SystemExit(result.returncode)


def windows_client_config(networks: list[ipaddress.IPv4Network]) -> str:
    routes = "".join(
        f'push "route {network.network_address} {network.netmask}"\n'
        for network in networks
    )
    return (
        f"ifconfig-push {WINDOWS_CLIENT[1]} 255.255.255.0\n"
        f"iroute {WINDOWS_LAN}\n"
        f"{routes}"
    )


def main() -> None:
    if os.geteuid() != 0:
        fail(f"Run this script as root: sudo python3 {Path(__file__).name}")
    ensure_ubuntu()
    os.umask(0o077)

    networks = [
        prompt_network("MikroTik A LAN", CLIENTS[0][1]),
        prompt_network("MikroTik B LAN", CLIENTS[1][1]),
    ]
    all_lans = [*networks, WINDOWS_LAN]
    endpoint = prompt_endpoint()
    port = prompt_port()

    if any(
        first.overlaps(second)
        for index, first in enumerate(all_lans)
        for second in all_lans[index + 1:]
    ):
        fail("MikroTik A, MikroTik B, and Windows LAN networks must not overlap.")
    if any(network.overlaps(DEFAULT_TUNNEL) for network in all_lans):
        fail(f"Neither LAN may overlap the OpenVPN tunnel network {DEFAULT_TUNNEL}.")

    print("\nThis will install OpenVPN/Easy-RSA and configure the VDS as a routed UDP/TUN hub.")
    print(
        f"Windows is a third routed site: LAN {WINDOWS_LAN}, "
        f"VPN IP {WINDOWS_CLIENT[1]}."
    )
    print("Existing server configuration files will be backed up; existing CA/private keys are preserved.")
    if input("Continue? [y/N]: ").strip().lower() not in ("y", "yes"):
        print("Cancelled.")
        return

    run(["apt-get", "update"])
    run(["apt-get", "install", "-y", "openvpn", "easy-rsa"])
    if not EASYRSA.exists():
        fail(f"Easy-RSA executable not found at {EASYRSA}.")
    openvpn_service, server_config = select_openvpn_service()

    OPENVPN_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    SERVER_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    SERVER_DIR.chmod(0o755)
    PKI_DIR.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not (PKI_DIR / "ca.crt").exists():
        if PKI_DIR.exists():
            if any(PKI_DIR.iterdir()):
                fail(f"Found an incomplete PKI at {PKI_DIR}; inspect it before continuing.")
            PKI_DIR.rmdir()
        easyrsa("init-pki")
        easyrsa("build-ca", "nopass", common_name="VDS OpenVPN CA")

    issue_certificate("server", "server")
    for name, *_ in CLIENTS:
        issue_certificate(name, "client")
    issue_certificate(WINDOWS_CLIENT[0], "client")

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    ccd_dir = SERVER_DIR / "ccd"
    for path in (server_config, SYSCTL_FILE):
        write_backup(path, timestamp)

    ccd_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    ccd_dir.chmod(0o755)
    for client, local_network, remote_network, tunnel_ip in (
        (CLIENTS[0][0], networks[0], networks[1], CLIENTS[0][3]),
        (CLIENTS[1][0], networks[1], networks[0], CLIENTS[1][3]),
    ):
        write_backup(ccd_dir / client, timestamp)
        ccd = (
            f"ifconfig-push {tunnel_ip} 255.255.255.0\n"
            f"iroute {local_network}\n"
            f'push "route {remote_network.network_address} {remote_network.netmask}"\n'
            f'push "route {WINDOWS_LAN.network_address} {WINDOWS_LAN.netmask}"\n'
        )
        atomic_write(ccd_dir / client, ccd, 0o644)

    write_backup(ccd_dir / WINDOWS_CLIENT[0], timestamp)
    atomic_write(ccd_dir / WINDOWS_CLIENT[0], windows_client_config(networks), 0o644)

    version_output = subprocess.run(
        ["openvpn", "--version"], capture_output=True, text=True, check=True
    ).stdout
    version_match = re.search(r"OpenVPN (\d+)\.(\d+)", version_output)
    if not version_match:
        fail("Could not determine the installed OpenVPN version.")
    openvpn_version = (int(version_match.group(1)), int(version_match.group(2)))
    data_ciphers = (
        "data-ciphers AES-256-CBC:AES-256-GCM:AES-128-GCM\n"
        if openvpn_version >= (2, 5)
        else ""
    )
    config = f"""port {port}
proto udp4
dev tun0
topology subnet
server {DEFAULT_TUNNEL.network_address} {DEFAULT_TUNNEL.netmask} nopool
ifconfig-pool 10.77.0.10 10.77.0.254 255.255.255.0
client-config-dir {ccd_dir}
client-to-client
route {networks[0].network_address} {networks[0].netmask}
route {networks[1].network_address} {networks[1].netmask}
route {WINDOWS_LAN.network_address} {WINDOWS_LAN.netmask}
ca {PKI_DIR}/ca.crt
cert {PKI_DIR}/issued/server.crt
key {PKI_DIR}/private/server.key
dh none
tls-version-min 1.2
verify-client-cert require
remote-cert-tls client
auth SHA256
cipher AES-256-CBC
{data_ciphers}keepalive 10 60
persist-key
persist-tun
user nobody
group nogroup
explicit-exit-notify 1
status /var/log/openvpn-status-server.log
verb 3
"""
    atomic_write(server_config, config)
    atomic_write(
        SYSCTL_FILE,
        "net.ipv4.ip_forward=1\n"
        "net.ipv4.conf.all.send_redirects=0\n"
        "net.ipv4.conf.default.send_redirects=0\n",
        0o644,
    )
    run(["sysctl", "--system"])

    profile_clients = (
        (CLIENTS[0][0], f"{CLIENTS[0][0]}.ovpn"),
        (CLIENTS[1][0], f"{CLIENTS[1][0]}.ovpn"),
        (WINDOWS_CLIENT[0], "windows.ovpn"),
    )
    CLIENT_OUTPUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    CLIENT_OUTPUT.chmod(0o700)
    for name, profile_name in profile_clients:
        client_ovpn = f"""client
dev tun
proto udp
remote {endpoint} {port}
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-256-CBC
verb 3
<ca>
{(PKI_DIR / "ca.crt").read_text(encoding="utf-8").strip()}
</ca>
<cert>
{(PKI_DIR / "issued" / f"{name}.crt").read_text(encoding="utf-8").strip()}
</cert>
<key>
{(PKI_DIR / "private" / f"{name}.key").read_text(encoding="utf-8").strip()}
</key>
"""
        client_profile = CLIENT_OUTPUT / profile_name
        write_backup(client_profile, timestamp)
        atomic_write(client_profile, client_ovpn)
        print(f"Created client profile: {client_profile}")

    run(["systemctl", "enable", openvpn_service])
    restart_openvpn_service(openvpn_service)
    if shutil.which("ufw") and subprocess.run(
        ["ufw", "status"], capture_output=True, text=True, check=True
    ).stdout.startswith("Status: active"):
        run(["ufw", "allow", f"{port}/udp"])
        for index, source in enumerate(all_lans):
            for destination in all_lans[index + 1:]:
                for source_network, destination_network in (
                    (source, destination),
                    (destination, source),
                ):
                    run([
                        "ufw", "route", "allow", "in", "on", "tun0", "out", "on", "tun0",
                        "from", str(source_network), "to", str(destination_network),
                    ])
        for network in all_lans:
            for source_network, destination_network in (
                (DEFAULT_TUNNEL, network),
                (network, DEFAULT_TUNNEL),
            ):
                run([
                    "ufw", "route", "allow", "in", "on", "tun0", "out", "on", "tun0",
                    "from", str(source_network), "to", str(destination_network),
                ])
    else:
        print(
            f"UFW is not active; allow inbound UDP/{port} and forwarding between "
            f"{', '.join(str(network) for network in all_lans)}."
        )

    print("\nOpenVPN hub deployed.")
    print(f"MikroTik A LAN: {networks[0]}; VPN IP: {CLIENTS[0][3]}")
    print(f"MikroTik B LAN: {networks[1]}; VPN IP: {CLIENTS[1][3]}")
    print(
        f"Windows LAN: {WINDOWS_LAN}; VPN IP: {WINDOWS_CLIENT[1]}"
    )
    print(f"Tunnel subnet: {DEFAULT_TUNNEL}; UDP port: {port}; no NAT rules are added.")
    print(
        "Enable IPv4 forwarding on Windows and configure its LAN-side gateway/devices "
        "to use Windows as their router."
    )
    print(
        "Ensure MikroTik A/B have routes to the Windows LAN via their OpenVPN interfaces "
        "and allow routed traffic in their firewalls."
    )
    print("Allow the UDP port in the VDS provider firewall as well.")
    print(f"Check service: sudo systemctl status {openvpn_service}")
    print("Check connected clients: sudo cat /var/log/openvpn-status-server.log")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        fail(f"Command failed with exit code {error.returncode}: {error.cmd}")
