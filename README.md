# ZeroTrust Mesh

A Zero-Trust Network Micro-Segmentation Engine built with Rust, Tauri, and SvelteKit.

## Overview

ZeroTrust Mesh is a desktop application for Linux systems that implements zero-trust network micro-segmentation. It provides:

- **SPIFFE Identity Management**: X.509 certificates and JWT-SVIDs for service authentication
- **Policy Engine**: JSON-based policies with <10ms evaluation time
- **WireGuard Mesh**: Encrypted tunnels between services
- **eBPF Data Plane**: High-performance packet inspection and attack detection
- **Trust Scoring**: Dynamic 0.0-1.0 trust scores with TPM attestation support
- **Real-time Dashboard**: Attack visualization, service topology, and alert management

## Requirements

- **OS**: Linux (Ubuntu 22.04+, Debian 12+, Fedora 38+, Arch Linux)
- **Kernel**: 5.8+ (eBPF support required)
- **Hardware**: 
  - Minimum: 4GB RAM, 2 CPU cores, 5GB disk
  - Recommended: 8GB RAM, 4 CPU cores, TPM 2.0 chip

### Dependencies

```bash
# Ubuntu/Debian
sudo apt install libbpf-dev wireguard-tools tpm2-tools clang

# Fedora
sudo dnf install libbpf-devel wireguard-tools tpm2-tools clang

# Arch Linux
sudo pacman -S libbpf wireguard-tools tpm2-tools clang
```

## Installation

### From Source

```bash
# Clone repository
git clone https://github.com/your-org/zerotrust-mesh.git
cd zerotrust-mesh

# Install Rust dependencies
cargo build --release

# Install frontend dependencies
npm install

# Build the application
npm run build
cargo tauri build
```

### Running

```bash
# Development mode
npm run dev &
cargo tauri dev

# Production
./target/release/zerotrust-mesh
```

**Note**: Root privileges are required for eBPF and WireGuard operations.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      ZeroTrust Mesh                              │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ Identity    │  │ Policy      │  │ WireGuard   │             │
│  │ Provider    │  │ Engine      │  │ Controller  │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ eBPF Data   │  │ Attestation │  │ Dashboard   │             │
│  │ Plane       │  │ Verifier    │  │ UI          │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

## Features

### Identity Management (Feature Group A)
- SPIFFE ID format: `spiffe://<trust_domain>/<workload>`
- X.509 certificate generation with 24-hour validity
- JWT-SVID issuance with 15-minute expiration
- Private keys encrypted with AES-256-GCM

### Policy Engine (Feature Group B)
- JSON-based policy definition
- Conditions: source, destination, method, time, risk score
- Actions: Allow, Deny, RequireMFA, Log
- Rate limiting and time-based policies
- <10ms evaluation latency with caching

### WireGuard Mesh (Feature Group C)
- Automatic tunnel creation between services
- Virtual IP allocation (10.128.0.0/16)
- ChaCha20-Poly1305 encryption
- Automatic key rotation every 7 days

### eBPF Data Plane (Feature Group D)
- XDP-based packet filtering
- Attack detection:
  - SYN flood (>100 SYNs/sec)
  - Port scan (>50 ports in 10s)
  - HTTP flood (>1000 req/sec)
  - ICMP flood (>500 pings/sec)
- Dynamic blacklisting

### Trust Scoring (Feature Group E)
- Score: 0.0 to 1.0
- Components:
  - TPM attestation (40%)
  - Process integrity (25%)
  - Behavioral anomalies (20%)
  - Resource usage (15%)
- Actions based on thresholds:
  - >0.8: Full access
  - 0.5-0.8: Limited access
  - 0.3-0.5: Isolated
  - <0.3: Terminate

### Dashboard (Feature Group F)
- Real-time attack visualization
- Service mesh topology graph
- Alert management
- Trust score monitoring

## Configuration

Configuration is stored in TOML format at `/etc/zerotrust-mesh/config.toml`:

```toml
[identity]
trust_domain = "zerotrust.local"
jwt_expiration_seconds = 900

[policy]
default_action = "Deny"
cache_ttl_seconds = 5

[wireguard]
listen_port = 51820
virtual_subnet = "10.128.0.0/16"

[ebpf]
enabled = true
syn_flood_threshold = 100
port_scan_threshold = 50

[attestation]
tpm_enabled = true
full_access_threshold = 0.8
```

## Security Considerations

- **All keys encrypted at rest** with AES-256-GCM
- **No hardcoded credentials** in source code
- **All network traffic encrypted** via WireGuard
- **Input validation** on all user inputs
- **Audit logging** for all security events
- **Default deny** policy (zero-trust model)

## Course Outcome Mapping

| CO | Description | Implementation |
|----|-------------|---------------|
| CO1 | Classical cryptography | Fallback cipher modes |
| CO2 | Public-key crypto (RSA) | SPIFFE certificates, JWT signing |
| CO3 | Network scanning (Nmap) | Service discovery |
| CO4 | Security mechanisms | eBPF policy enforcement |
| CO5 | DoS/DDoS detection | Attack detection via trust scoring |

## License

MIT License - See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Support

For issues and feature requests, please use the GitHub issue tracker.
