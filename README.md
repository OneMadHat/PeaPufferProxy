# PeaPufferProxy (puffproxy)

PeaPufferProxy (puffproxy for short) is a small Go-based reverse proxy manager with a built-in admin UI.

## Features

- HTTP/HTTPS reverse proxy with optional WebSocket support
- Per-host TLS (Let's Encrypt or custom certificates)
- Optional per-host authentication
- Per-host exploit protection headers (toggle each header)
- Built-in security controls (WAF screening, origin shielding, IP allow/deny lists, per-host rate limits)
- Health checks and simple round-robin across backends
- Admin UI for managing hosts, certificates, users, and logs

## Getting Started

### Requirements

- Go 1.25+
- Ports `80`, `443`, and `8081` available (run as root or with appropriate permissions)

### Run

```bash
go run .
```

The admin UI is served on `http://localhost:8081/admin`.

## Configuration

Configuration is stored in `proxy_config.json` in the working directory. The app will normalize
older formats on startup (e.g., array-based host lists) and rewrite the file.

On first start, puffproxy creates a default `admin` user. The generated password is written in
plaintext to `.admin_credentials` in the working directory, and the hashed password is stored in
`proxy_config.json` under `users`.

Example:

```json
{
  "hosts": {
    "example.com": {
      "backends": ["http://127.0.0.1:8080"],
      "ssl": true,
      "auto_cert": true,
      "websocket": true,
      "require_auth": false,
      "waf_enabled": true,
      "origin_shield": true,
      "rate_limit_per_minute": 120,
      "allowlist": ["192.168.1.0/24"],
      "denylist": ["203.0.113.0/24"],
      "exploit_blocks": {
        "frame_options": true,
        "xss_protection": true,
        "content_type_options": true,
        "content_security_policy": true,
        "strict_transport_security": true,
        "referrer_policy": true
      }
    }
  },
  "certs": {},
  "users": {
    "admin": "$2a$10$hash-here"
  }
}
```

## Notes

- The admin UI supports multiple backends per host with selectable load-balancing strategies.
- TLS certificates are stored under the `certs/` directory.
