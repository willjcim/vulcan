# Vulcan

## Overview

Vulcan is a Network Traffic simulation tool that can be used to generate text-based hexdumps of packets as well as native libpcap format packet captures.

## Quickstart

### Local development

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .
pytest
python -m vulcan.app  # local dev server on http://127.0.0.1:5000
```

### Docker

```bash
docker compose up --build
curl http://localhost:9200/healthz
```

## Configuration

All knobs are environment variables (see [`docker/vulcan.env.example`](docker/vulcan.env.example)):

| Variable | Default | Description |
| --- | --- | --- |
| `VULCAN_LOG_LEVEL` | `INFO` | Standard Python log level |
| `VULCAN_JSON_LOGS` | `true` | Emit logs as JSON (recommended for production) |
| `VULCAN_CORS_ORIGINS` | _empty_ | Comma-separated allow-list, empty disables cross-origin browser access |
| `VULCAN_API_TOKEN` | _empty_ | If set, every request must send `X-API-Token: <token>` or `Authorization: Bearer <token>` |
| `VULCAN_MAX_CONTENT_LENGTH` | `1048576` | Max request body in bytes (1 MiB) |
| `VULCAN_RATE_LIMIT_DEFAULT` | `60/minute` | Default per-IP rate limit |
| `VULCAN_RATE_LIMIT_CREATE_PCAP` | `10/minute` | Per-IP rate limit for `/create-pcap` |
| `VULCAN_RATE_LIMIT_STORAGE_URI` | `memory://` | Set to `redis://...` for multi-worker deployments |

## Endpoints

### `GET /healthz`

Liveness probe

```json
{ "status": "ok", "version": "0.2.0" }
```

### `GET /get-uptime`

Returns the service's current uptime.

```json
{ "success": "uptime: 21 days, 0:32:59.665307" }
```

### `POST /create-pcap`

**Accepts:** JSON as a list of packet objects

**Returns:** PCAP file (`Content-Type: application/vnd.tcpdump.pcap`)

**Error responses:** JSON of the form

```json
{
  "error": "Request validation failed.",
  "details": [{ "loc": ["0", "evil"], "msg": "Extra inputs are not permitted", "type": "extra_forbidden" }],
  "request_id": "abf3eb0f3294f944"
}
```

#### Required Packet Object Fields

**Session:** Used for stream tracking

```json
"session": {
    "id": "1"
}
```

**Autofill:** Indicates if Vulcan should fill in frame/packet gaps to make the network traffic valid (experimental)

```json
"autofill": {
    "enabled": true
}
```

**Frame Object:** At least one transport from the optional frame objects is required to create the packet

### Frame Objects

Frames will accept any number of args that may be passed to the corresponding Scapy class

#### Examples

**ether:** Ethernet frame

```json
"ether": {
    "dst": "00:00:00:00:00:00",
    "src": "ff:ff:ff:ff:ff:ff",
    "type": "ipv4"
}
```

**ip:** IP frame

```json
"ip": {
    "src": "10.10.10.10",
    "dst": "10.10.10.11",
    "ttl": "32",
    "version": "4"
}
```

**tcp:** TCP frame

```json
"tcp": {
    "sport": "25565",
    "dport": "80",
    "seq": "0",
    "ack": "1",
    "flags": "PA",
    "window": "65535"
}
```

**udp:** UDP frame

```json
"udp": {
    "sport": "25565",
    "dport": "80"
}
```

**icmp:** ICMP frame

```json
"icmp": {
    "type": "8",
    "code": "1",
    "id": "1",
    "seq": "1"
}
```

**dns:** DNS frame

```json
"dns": {
    "qname": "example.com",
    "qtype": "A",
    "rd": "1",
    "qr": "0",
    "answers": "179.23.99.1"
}
```

**HTTP Request:** HTTP Request frame

```json
"http_request": {
    "headers": "Cache:nocache",
    "method": "GET",
    "path": "/",
    "version": "1.1"
}
```

**HTTP Response:** HTTP Response frame

```json
"http_response": {
    "headers": "Cache:nocache",
    "code": "200",
    "reason": "OK",
    "version": "1.1"
}
```

**raw:** Payload frame

Hex payloads may be optionally delimited with spaces and optionally prefixed with '\x' or '0x'

```json
"raw": {
    "payload": "example"
}
```

**Full example:**

```json
[
  {
    "session": {
      "id": "1"
    },
    "autofill": {
      "enabled": false
    },
    "ether": {
      "type": "ipv4"
    },
    "ip": {
      "version": "4"
    },
    "tcp": {
      "sport": "12345",
      "dport": "80",
      "seq": "0",
      "ack": "0",
      "flags": "S",
      "window": "65535"
    }
  },
  {
    "session": {
      "id": "1"
    },
    "autofill": {
      "enabled": false
    },
    "ether": {
      "type": "ipv4"
    },
    "ip": {
      "version": "4"
    },
    "tcp": {
      "sport": "80",
      "dport": "12345",
      "seq": "0",
      "ack": "1",
      "flags": "SA",
      "window": "65535"
    }
  },
  {
    "session": {
      "id": ""
    },
    "autofill": {
      "enabled": false
    },
    "ether": {
      "type": "ipv4"
    },
    "ip": {
      "version": "4"
    },
    "tcp": {
      "sport": "12345",
      "dport": "80",
      "seq": "1",
      "ack": "1",
      "flags": "A",
      "window": "8192"
    }
  }
]
```