#!/usr/bin/env python3
"""Prepare MikroTik OpenVPN files in build/ using the CRSF2 technical-task LANs."""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import os
import tempfile
from pathlib import Path

import ovpn_to_rsc


SITE_NETWORKS = {
    "a": (
        ipaddress.ip_network("192.168.66.0/24"),
        ipaddress.ip_network("192.168.55.0/24"),
    ),
    "b": (
        ipaddress.ip_network("192.168.55.0/24"),
        ipaddress.ip_network("192.168.66.0/24"),
    ),
}
WINDOWS_LAN = ipaddress.ip_network("192.168.11.0/24")
CLIENT_PROFILES = ("mikrotik-a", "mikrotik-b", "windows")


def atomic_write(path: Path, content: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(content)
        temporary_path.chmod(mode)
        temporary_path.replace(path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Regenerate build/ MikroTik RSC files for point A "
            "(192.168.66.0/24) and point B (192.168.55.0/24)."
        )
    )
    root = Path(__file__).resolve().parent
    parser.add_argument("--source-dir", type=Path, default=root / "downl")
    parser.add_argument("--output-dir", type=Path, default=root / "build")
    args = parser.parse_args()

    sources = {
        name: args.source_dir / f"{name}.ovpn"
        for name in CLIENT_PROFILES
    }
    missing = [path for path in sources.values() if not path.is_file()]
    if missing:
        parser.error("Missing input profile(s): " + ", ".join(str(path) for path in missing))

    try:
        parsed_profiles = {}
        for name, path in sources.items():
            contents = path.read_text(encoding="utf-8")
            endpoint, port, protocol, needs_user_password = ovpn_to_rsc.parse_profile(contents)
            parsed_profiles[name] = (endpoint, port, protocol, needs_user_password)

        router_scripts = {}
        for site in ("a", "b"):
            client_name = f"mikrotik-{site}"
            local_network, remote_network = SITE_NETWORKS[site]
            endpoint, port, protocol, needs_user_password = parsed_profiles[client_name]
            password = (
                getpass.getpass(f"OVPN password for {client_name}: ")
                if needs_user_password
                else ""
            )
            script = ovpn_to_rsc.build_script(
                profile_name=f"{client_name}.ovpn",
                interface_name=f"ovpn-vds-{site}",
                username=client_name,
                password=password,
                local_network=local_network,
                remote_network=remote_network,
                additional_networks=(WINDOWS_LAN,),
            )
            router_scripts[client_name] = script
            print(
                f"{client_name}: {local_network} -> {remote_network}; "
                f"VDS {endpoint}:{port}/{protocol}"
            )

        args.output_dir.mkdir(parents=True, exist_ok=True)
        for name in CLIENT_PROFILES:
            atomic_write(
                args.output_dir / f"{name}.ovpn",
                sources[name].read_bytes(),
            )
        for client_name, script in router_scripts.items():
            atomic_write(
                args.output_dir / f"{client_name}.rsc",
                script.encode("utf-8"),
            )
    except (OSError, ValueError, ovpn_to_rsc.ProfileError) as error:
        print(f"ERROR: {error}")
        return 1

    print(f"\nPrepared RouterOS files in: {args.output_dir}")
    print("Upload each matching .ovpn and .rsc pair to its MikroTik.")
    print(
        "MikroTik RSC files include a route to Windows LAN 192.168.11.0/24. "
        "The VDS must be deployed with A 192.168.66.0/24, B 192.168.55.0/24, "
        "and Windows LAN 192.168.11.0/24. Enable Windows IPv4 forwarding."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
