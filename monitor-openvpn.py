#!/usr/bin/env python3
"""Report OpenVPN service and client connection status on the VDS."""

from __future__ import annotations

import argparse
import csv
import io
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


DEFAULT_STATUS_FILE = Path("/var/log/openvpn-status-server.log")
SERVICE_CANDIDATES = (
    "openvpn-server@server.service",
    "openvpn@server.service",
)
EXPECTED_CLIENTS = {
    "mikrotik-a": "MikroTik A",
    "mikrotik-b": "MikroTik B",
    "windows-client": "Windows",
}


@dataclass
class Client:
    common_name: str
    real_address: str = "unknown"
    virtual_address: str = "unknown"
    bytes_received: int = 0
    bytes_sent: int = 0
    connected_since: str = "unknown"


def systemctl_value(*arguments: str) -> str:
    result = subprocess.run(
        ["systemctl", *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        return ""
    return result.stdout.strip()


def find_service(override: str | None) -> tuple[str | None, str]:
    candidates = (override,) if override else SERVICE_CANDIDATES
    for service in candidates:
        load_state = systemctl_value("show", "--property=LoadState", "--value", service)
        if load_state == "loaded":
            active_state = systemctl_value(
                "show", "--property=ActiveState", "--value", service
            )
            return service, active_state or "unknown"
    return None, "not-found"


def parse_byte_count(value: str) -> int:
    try:
        return max(0, int(value))
    except ValueError:
        return 0


def parse_clients(contents: str) -> dict[str, Client]:
    clients: dict[str, Client] = {}
    client_headers: list[str] | None = None

    for row in csv.reader(io.StringIO(contents)):
        if not row:
            continue
        if row[0] == "HEADER" and len(row) > 1 and row[1] == "CLIENT_LIST":
            client_headers = row[2:]
            continue
        if row[0] != "CLIENT_LIST" or len(row) < 2:
            continue

        values = row[1:]
        if client_headers:
            record = {
                header.strip().lower().replace(" ", "_"): values[index]
                for index, header in enumerate(client_headers)
                if index < len(values)
            }
            common_name = (
                record.get("common_name")
                or record.get("commonname")
                or record.get("name")
                or ""
            )
            real_address = record.get("real_address", "unknown")
            virtual_address = record.get("virtual_address", "unknown")
            received = record.get("bytes_received", "0")
            sent = record.get("bytes_sent", "0")
            connected_since = (
                record.get("connected_since")
                or record.get("connected_since_time_t")
                or "unknown"
            )
        else:
            # OpenVPN status format 1:
            # CLIENT_LIST,Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
            common_name = values[0]
            real_address = values[1] if len(values) > 1 else "unknown"
            virtual_address = "unknown"
            received = values[2] if len(values) > 2 else "0"
            sent = values[3] if len(values) > 3 else "0"
            connected_since = values[4] if len(values) > 4 else "unknown"

        if common_name:
            clients[common_name] = Client(
                common_name=common_name,
                real_address=real_address,
                virtual_address=virtual_address,
                bytes_received=parse_byte_count(received),
                bytes_sent=parse_byte_count(sent),
                connected_since=connected_since,
            )

    return clients


def format_bytes(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(value)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{value} B"


def monitor_once(status_file: Path, service_override: str | None) -> bool:
    service, state = find_service(service_override)
    service_label = service or service_override or "OpenVPN systemd unit"
    active = state == "active"
    print(f"OpenVPN service: {'ACTIVE' if active else state.upper()} ({service_label})")

    try:
        contents = status_file.read_text(encoding="utf-8")
        modified = datetime.fromtimestamp(status_file.stat().st_mtime).astimezone()
    except OSError as error:
        print(f"Status file: unavailable ({error})")
        return False

    age_seconds = max(0, int(time.time() - status_file.stat().st_mtime))
    print(f"Status file: {status_file} (updated {modified:%Y-%m-%d %H:%M:%S %Z}, {age_seconds}s ago)")
    clients = parse_clients(contents)

    for common_name, label in EXPECTED_CLIENTS.items():
        client = clients.get(common_name)
        if client is None:
            print(f"{label}: DISCONNECTED")
            continue
        print(
            f"{label}: CONNECTED"
            f" | tunnel IP {client.virtual_address}"
            f" | remote {client.real_address}"
            f" | since {client.connected_since}"
            f" | received {format_bytes(client.bytes_received)}"
            f" | sent {format_bytes(client.bytes_sent)}"
        )

    for common_name, client in clients.items():
        if common_name not in EXPECTED_CLIENTS:
            print(
                f"Other client {common_name}: CONNECTED"
                f" | tunnel IP {client.virtual_address}"
                f" | remote {client.real_address}"
                f" | received {format_bytes(client.bytes_received)}"
                f" | sent {format_bytes(client.bytes_sent)}"
            )

    if age_seconds > 120:
        print("WARNING: status file is stale; check the OpenVPN service and status configuration.")
    return active


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Show OpenVPN service and connected clients on the deployed VDS."
    )
    parser.add_argument(
        "--status-file",
        type=Path,
        default=DEFAULT_STATUS_FILE,
        help=f"OpenVPN status log (default: {DEFAULT_STATUS_FILE})",
    )
    parser.add_argument(
        "--service",
        help="systemd service name; by default the deployed OpenVPN unit is detected",
    )
    parser.add_argument(
        "--watch",
        type=int,
        metavar="SECONDS",
        help="refresh the status repeatedly at this interval",
    )
    args = parser.parse_args()
    if args.watch is not None and args.watch < 1:
        parser.error("--watch interval must be a positive number of seconds")

    if args.watch is None:
        return 0 if monitor_once(args.status_file, args.service) else 1

    try:
        while True:
            print(f"\n--- {datetime.now().astimezone():%Y-%m-%d %H:%M:%S %Z} ---")
            monitor_once(args.status_file, args.service)
            time.sleep(args.watch)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
