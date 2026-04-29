from __future__ import annotations

import random
import secrets
from typing import Union

from vulcan import constants
from vulcan.logger import get_logger

logger = get_logger(__name__)

PortInput = Union[str, int]


def check_port(port: PortInput) -> int:
    """validate a user supplied port value

    Accepts:
      - an integer (or numeric string) in 1-65535
      - the literal "any"
      - a $variable reference valid in :mod: vulcan.constants

    Raises:
        ValueError: for any other input
    """
    if isinstance(port, int):
        if 1 <= port <= 65535:
            return port
        raise ValueError(f"Invalid port value ({port}). Valid range 1-65535")

    if not isinstance(port, str):
        raise ValueError(f"Invalid port value ({port!r}). Must be int or str")

    stripped = port.strip()
    if not stripped:
        raise ValueError("Invalid port value (empty string)")

    if stripped.lstrip("-").isdigit():
        port_int = int(stripped)
        if 1 <= port_int <= 65535:
            return port_int
        raise ValueError(f"Invalid port value ({port}). Valid range 1-65535")

    lowered = stripped.lower()
    if lowered == "any":
        return random.randint(1024, 65535)

    if lowered.startswith("$"):
        choices = constants.TCP_PORTS.get(lowered)
        if not choices:
            logger.warning("Unknown port variable %s - falling back to ephemeral range", lowered)
            return random.randint(1024, 65535)
        return random.choice(choices)

    raise ValueError(f"Invalid port option ({port}). Valid options: any, 1-65535, $variable_ports")


def safe_filename(prefix: str = "vulcan", suffix: str = ".pcap") -> str:
    """
    return a cryptographically random filename
    """
    return f"{prefix}-{secrets.token_hex(8)}{suffix}"
