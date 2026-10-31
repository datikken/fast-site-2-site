#!/usr/bin/env python3
"""Report OpenVPN service and client connection status on the VDS."""

from __future__ import annotations

import argparse
import csv
import io
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


DEFAULT_STATUS_FILES = (
    Path("/run/openvpn-server/status-server.log"),
    Path("/var/log/openvpn-status-server.log"),
)
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


def render_table(clients: dict[str, Client]) -> str:
    rows = []
    for common_name, label in EXPECTED_CLIENTS.items():
        client = clients.get(common_name)
        if client is None:
            rows.append((label, "OFFLINE", "-", "-", "-", "-", "-"))
        else:
            rows.append(
                (
                    label,
                    "ONLINE",
                    client.virtual_address,
                    client.real_address,
                    client.connected_since,
                    format_bytes(client.bytes_received),
                    format_bytes(client.bytes_sent),
                )
            )

    for common_name, client in clients.items():
        if common_name not in EXPECTED_CLIENTS:
            rows.append(
                (
                    common_name,
                    "ONLINE",
                    client.virtual_address,
                    client.real_address,
                    client.connected_since,
                    format_bytes(client.bytes_received),
                    format_bytes(client.bytes_sent),
                )
            )

    headers = ("CLIENT", "STATUS", "VPN IP", "REMOTE ADDRESS", "CONNECTED SINCE", "RECEIVED", "SENT")
    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(headers)
    ]
    terminal_width = shutil.get_terminal_size((120, 24)).columns
    max_remote_width = max(18, terminal_width - sum(widths) + widths[3] - 8)
    widths[3] = min(widths[3], max_remote_width, 32)
    rows = [
        tuple(value if len(value) <= widths[index] else value[: widths[index] - 1] + "…" for index, value in enumerate(row))
        for row in rows
    ]

    def format_row(values: tuple[str, ...]) -> str:
        return "  " + "  ".join(value.ljust(widths[index]) for index, value in enumerate(values))

    separator = "  " + "  ".join("-" * width for width in widths)
    return "\n".join((format_row(headers), separator, *(format_row(row) for row in rows)))


def resolve_status_file(status_file: Path | None) -> Path:
    if status_file is not None:
        return status_file
    available = [path for path in DEFAULT_STATUS_FILES if path.is_file()]
    if not available:
        return DEFAULT_STATUS_FILES[0]
    return max(available, key=lambda path: path.stat().st_mtime)


def monitor_once(status_file: Path | None, service_override: str | None) -> bool:
    service, state = find_service(service_override)
    service_label = service or service_override or "OpenVPN systemd unit"
    active = state == "active"
    status_path = resolve_status_file(status_file)

    try:
        contents = status_path.read_text(encoding="utf-8")
        modified_timestamp = status_path.stat().st_mtime
    except OSError as error:
        print(f"OpenVPN service: {'ACTIVE' if active else state.upper()} ({service_label})")
        print(f"Status file unavailable ({status_path}): {error}")
        return False

    modified = datetime.fromtimestamp(modified_timestamp).astimezone()
    age_seconds = max(0, int(time.time() - modified_timestamp))
    clients = parse_clients(contents)

    print(f"OpenVPN service: {'ACTIVE' if active else state.upper()} ({service_label})")
    print(
        f"Status file: {status_path} | updated {modified:%Y-%m-%d %H:%M:%S %Z} "
        f"({age_seconds}s ago) | Connected clients: {len(clients)}"
    )
    print(render_table(clients))
    if age_seconds > 120:
        print("WARNING: status file is stale; check the OpenVPN service and status configuration.")
    return active


def watch(status_file: Path | None, service: str | None, interval: int) -> int:
    try:
        while True:
            if sys.stdout.isatty():
                sys.stdout.write("\033[2J\033[H")
            else:
                print()
            print(f"OpenVPN monitor | {datetime.now().astimezone():%Y-%m-%d %H:%M:%S %Z}")
            print("Press Ctrl+C to exit.\n")
            monitor_once(status_file, service)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Show OpenVPN service and connected clients on the deployed VDS."
    )
    parser.add_argument(
        "--status-file",
        type=Path,
        default=None,
        help=(
            "OpenVPN status log (default: auto-detect the most recently updated file "
            f"from {', '.join(map(str, DEFAULT_STATUS_FILES))})"
        ),
    )
    parser.add_argument(
        "--service",
        help="systemd service name; by default the deployed OpenVPN unit is detected",
    )
    parser.add_argument(
        "--watch",
        type=int,
        nargs="?",
        const=5,
        metavar="SECONDS",
        help="refresh continuously (default interval: 5 seconds; optionally provide seconds)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        metavar="SECONDS",
        help="refresh interval for continuous monitoring (default: 5)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="show one status table and exit instead of monitoring continuously",
    )
    args = parser.parse_args()
    interval = args.watch if args.watch is not None else args.interval
    if interval < 1:
        parser.error("refresh interval must be a positive number of seconds")
    if args.watch is not None and args.interval != 5:
        parser.error("use either --watch SECONDS or --interval SECONDS, not both")
    if args.once and args.watch is not None:
        parser.error("--once cannot be combined with --watch")

    if args.once:
        return 0 if monitor_once(args.status_file, args.service) else 1

    return watch(args.status_file, args.service, interval)


if __name__ == "__main__":
    raise SystemExit(main())
