#!/usr/bin/env python3
"""Create a MikroTik RouterOS script to import an OpenVPN UDP/TUN profile."""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import os
import re
import shlex
import shutil
import sys
from pathlib import Path


SITE_NETWORKS = {
    "a": (ipaddress.ip_network("192.168.10.0/24"), ipaddress.ip_network("192.168.20.0/24")),
    "b": (ipaddress.ip_network("192.168.20.0/24"), ipaddress.ip_network("192.168.10.0/24")),
}
VPN_NETWORK = ipaddress.ip_network("10.77.0.0/24")
INLINE_BLOCK = re.compile(r"^<(/?)([A-Za-z0-9_-]+)>$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


class ProfileError(ValueError):
    pass


def parse_profile(content: str) -> tuple[str, int, str, bool]:
    directives: list[list[str]] = []
    blocks: set[str] = set()
    current_block: str | None = None

    for line_number, raw_line in enumerate(content.lstrip("\ufeff").splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        block_match = INLINE_BLOCK.fullmatch(line)
        if block_match:
            closing, block_name = block_match.groups()
            if closing:
                if current_block != block_name:
                    raise ProfileError(f"Unexpected closing block on line {line_number}.")
                current_block = None
            else:
                if current_block is not None:
                    raise ProfileError(f"Nested inline block on line {line_number}.")
                current_block = block_name
                blocks.add(block_name)
            continue
        if current_block is not None or line.startswith("#") or line.startswith(";"):
            continue
        try:
            tokens = shlex.split(line, comments=True, posix=True)
        except ValueError as error:
            raise ProfileError(f"Invalid quoting on line {line_number}: {error}") from error
        if tokens:
            directives.append(tokens)

    if current_block is not None:
        raise ProfileError(f"Unclosed <{current_block}> block.")

    remotes = [tokens for tokens in directives if tokens[0] == "remote"]
    if len(remotes) != 1 or len(remotes[0]) < 2:
        raise ProfileError("Expected exactly one 'remote host [port]' directive.")
    endpoint = remotes[0][1]
    port = 1194
    if len(remotes[0]) >= 3:
        try:
            port = int(remotes[0][2])
        except ValueError as error:
            raise ProfileError("The remote port must be an integer.") from error
    if not 1 <= port <= 65535:
        raise ProfileError("The remote port must be between 1 and 65535.")

    protocols = [tokens[1].lower() for tokens in directives if tokens[0] == "proto" and len(tokens) > 1]
    if protocols != ["udp"] and protocols != ["udp4"]:
        raise ProfileError("This converter supports OpenVPN over UDP/IPv4 only.")
    devices = [tokens[1].lower() for tokens in directives if tokens[0] == "dev" and len(tokens) > 1]
    if not devices or any(not device.startswith("tun") for device in devices):
        raise ProfileError("This converter supports TUN (Layer 3), not TAP.")
    if not {"ca", "cert", "key"}.issubset(blocks):
        raise ProfileError("Expected inline <ca>, <cert>, and <key> blocks in the .ovpn file.")
    auth_user_pass = any(tokens[0] == "auth-user-pass" for tokens in directives)

    return endpoint, port, protocols[0], auth_user_pass


def routeros_quote(value: str) -> str:
    if any(ord(character) < 32 for character in value):
        raise ProfileError("RouterOS values cannot contain control characters.")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_script(
    *,
    profile_name: str,
    interface_name: str,
    username: str,
    password: str,
    local_network: ipaddress.IPv4Network,
    remote_network: ipaddress.IPv4Network,
) -> str:
    if local_network.overlaps(remote_network):
        raise ProfileError("Local and remote LAN networks must not overlap.")

    profile = routeros_quote(profile_name)
    interface = routeros_quote(interface_name)
    user = routeros_quote(username)
    secret = routeros_quote(password)
    local = routeros_quote(str(local_network))
    remote = routeros_quote(str(remote_network))
    vpn_network = routeros_quote(str(VPN_NETWORK))
    route_comment = routeros_quote(f"OpenVPN {interface_name} to {remote_network}")
    nat_comment = routeros_quote(f"OpenVPN no NAT {local_network} to {remote_network}")
    nat_windows_out_comment = routeros_quote(
        f"OpenVPN no NAT {local_network} to Windows clients"
    )
    nat_windows_in_comment = routeros_quote(
        f"OpenVPN no NAT Windows clients to {local_network}"
    )
    forward_out_comment = routeros_quote(f"OpenVPN forward {local_network} to {remote_network}")
    forward_in_comment = routeros_quote(f"OpenVPN forward {remote_network} to {local_network}")
    forward_windows_in_comment = routeros_quote(
        f"OpenVPN forward Windows clients to {local_network}"
    )
    forward_windows_out_comment = routeros_quote(
        f"OpenVPN forward {local_network} to Windows clients"
    )

    return f"""# RouterOS 7.17+ is required for OpenVPN over UDP.
# Upload {profile_name} to the router's Files list before importing this script.
# OpenVPN user/password are only needed if the server requests user authentication.
:local sourceFile {profile}
:local interfaceName {interface}
:local localNetwork {local}
:local remoteNetwork {remote}
:local vpnNetwork {vpn_network}
:local existing [/interface ovpn-client find where name=$interfaceName]
:if ([:len $existing] > 0) do={{ :error ("OVPN interface already exists: " . $interfaceName) }}
:local oldCount [:len [/interface ovpn-client find]]
/interface ovpn-client import-ovpn-configuration file-name=$sourceFile ovpn-user={user} ovpn-password={secret} skip-cert-import=no
:delay 2s
:local clients [/interface ovpn-client find]
:if ([:len $clients] <= $oldCount) do={{ :error "OVPN import did not create an interface" }}
:local newId [:pick $clients ([:len $clients] - 1)]
/interface ovpn-client set $newId name=$interfaceName disabled=no
:if ([:len [/ip route find where dst-address=$vpnNetwork and gateway=$interfaceName]] = 0) do={{
    /ip route add dst-address=$vpnNetwork gateway=$interfaceName comment="OpenVPN route to VPN clients"
}}
:if ([:len [/ip route find where dst-address=$remoteNetwork and gateway=$interfaceName]] = 0) do={{
    /ip route add dst-address=$remoteNetwork gateway=$interfaceName comment={route_comment}
}}
:if ([:len [/ip firewall nat find where comment={nat_comment}]] = 0) do={{
    /ip firewall nat add chain=srcnat action=accept src-address=$localNetwork dst-address=$remoteNetwork comment={nat_comment} place-before=0
}}
:if ([:len [/ip firewall nat find where comment={nat_windows_out_comment}]] = 0) do={{
    /ip firewall nat add chain=srcnat action=accept src-address=$localNetwork dst-address=$vpnNetwork comment={nat_windows_out_comment} place-before=0
}}
:if ([:len [/ip firewall nat find where comment={nat_windows_in_comment}]] = 0) do={{
    /ip firewall nat add chain=srcnat action=accept src-address=$vpnNetwork dst-address=$localNetwork comment={nat_windows_in_comment} place-before=0
}}
:if ([:len [/ip firewall filter find where comment={forward_out_comment}]] = 0) do={{
    /ip firewall filter add chain=forward action=accept src-address=$localNetwork dst-address=$remoteNetwork comment={forward_out_comment} place-before=0
}}
:if ([:len [/ip firewall filter find where comment={forward_in_comment}]] = 0) do={{
    /ip firewall filter add chain=forward action=accept src-address=$remoteNetwork dst-address=$localNetwork comment={forward_in_comment} place-before=0
}}
:if ([:len [/ip firewall filter find where comment={forward_windows_in_comment}]] = 0) do={{
    /ip firewall filter add chain=forward action=accept src-address=$vpnNetwork dst-address=$localNetwork comment={forward_windows_in_comment} place-before=0
}}
:if ([:len [/ip firewall filter find where comment={forward_windows_out_comment}]] = 0) do={{
    /ip firewall filter add chain=forward action=accept src-address=$localNetwork dst-address=$vpnNetwork comment={forward_windows_out_comment} place-before=0
}}
"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert an OpenVPN UDP/TUN profile into a RouterOS .rsc import script."
    )
    parser.add_argument("profile", type=Path, help="Input .ovpn file")
    parser.add_argument(
        "--site", choices=("a", "b"), default="a",
        help="Project site; selects the default local/remote LANs (default: a)",
    )
    parser.add_argument("--output", type=Path, help="Output .rsc path (default: alongside the input)")
    parser.add_argument("--interface", help="RouterOS OVPN interface name (default: ovpn-vds-<site>)")
    parser.add_argument("--username", help="OVPN username; defaults to mikrotik-<site>")
    parser.add_argument(
        "--password",
        help="OVPN password; if the profile uses auth-user-pass and this is omitted, prompt securely",
    )
    parser.add_argument("--local-network", help="Local LAN CIDR (defaults to the selected project site)")
    parser.add_argument("--remote-network", help="Remote LAN CIDR (defaults to the selected project site)")
    parser.add_argument("--force", action="store_true", help="Overwrite existing output files")
    args = parser.parse_args()

    try:
        content = args.profile.read_text(encoding="utf-8")
        endpoint, port, protocol, needs_user_password = parse_profile(content)
        default_local, default_remote = SITE_NETWORKS[args.site]
        local_network = ipaddress.ip_network(args.local_network or str(default_local), strict=True)
        remote_network = ipaddress.ip_network(args.remote_network or str(default_remote), strict=True)
        if not isinstance(local_network, ipaddress.IPv4Network) or not isinstance(
            remote_network, ipaddress.IPv4Network
        ):
            raise ProfileError("LAN networks must be IPv4.")

        interface_name = args.interface or f"ovpn-vds-{args.site}"
        if not SAFE_NAME.fullmatch(interface_name):
            raise ProfileError("Interface name must be 1-32 ASCII letters, digits, '.', '_' or '-'.")

        username = args.username or f"mikrotik-{args.site}"
        password = args.password
        if password is None:
            password = getpass.getpass("OVPN password (press Enter if certificate-only): ") if needs_user_password else ""

        output = args.output or args.profile.with_suffix(".rsc")
        copied_profile = output.parent / args.profile.name
        if output.resolve() != args.profile.resolve() and output.exists() and not args.force:
            raise ProfileError(f"Output already exists: {output} (use --force to overwrite).")
        if copied_profile.resolve() != args.profile.resolve() and copied_profile.exists() and not args.force:
            raise ProfileError(
                f"Profile copy already exists: {copied_profile} (use --force to overwrite)."
            )
        if copied_profile.resolve() != args.profile.resolve():
            copied_profile.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(args.profile, copied_profile)
            os.chmod(copied_profile, 0o600)

        script = build_script(
            profile_name=copied_profile.name,
            interface_name=interface_name,
            username=username,
            password=password,
            local_network=local_network,
            remote_network=remote_network,
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(script, encoding="utf-8", newline="\r\n")
        os.chmod(output, 0o600)
    except (OSError, ValueError, ProfileError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"OpenVPN endpoint: {endpoint}:{port}/{protocol}")
    print(f"Created RouterOS script: {output}")
    print(f"Copied profile for router Files list: {copied_profile}")
    print("Upload both files to the MikroTik, then run: /import file-name=" + output.name)
    if password:
        print("The generated .rsc contains the supplied OVPN password; transfer and store it securely.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
