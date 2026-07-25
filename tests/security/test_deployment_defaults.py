from __future__ import annotations

from pathlib import Path

import yaml


def test_compose_fixture_port_is_loopback_only_by_default() -> None:
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    service = compose["services"]["toxicjoin"]
    ports = tuple(str(port) for port in service["ports"])

    assert ports == ("127.0.0.1:${TOXICJOIN_PUBLIC_PORT:-8000}:8000",)
    assert all(not port.startswith("${TOXICJOIN_PUBLIC_PORT") for port in ports)
