# IPMI Desktop Manager

Native desktop application for managing Supermicro server BMCs via IPMI and Redfish — no Java required.

Built with [Tauri 2.x](https://v2.tauri.app/) (Rust backend + vanilla HTML/CSS/JS frontend). Single binary, ~5 MB installer.

![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)
![Tauri](https://img.shields.io/badge/Tauri-2.x-orange)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

### Connection
- **Redfish REST API** (primary) + **IPMI 2.0** (fallback) with auto-negotiation
- Protocol modes: Auto / Redfish Only / IPMI Only
- TLS certificate verification toggle for self-signed BMC certs
- Credentials stored securely in OS keychain (Windows Credential Manager / macOS Keychain / Linux Secret Service)

### Management
- **Dashboard** — system info, CPU/memory, power state, thermal overview at a glance
- **Power Control** — power on, off, cycle, graceful shutdown, force off, hard reset
- **Boot Order** — set next boot device (HDD, PXE, BIOS Setup, etc.)

### Monitoring
- **Sensor Monitor** — real-time temperature, voltage, fan speed readings with auto-refresh
- **Event Log (SEL)** — view and clear System Event Log entries

### Tools
- **Serial over LAN (SOL)** — interactive BMC terminal console via IPMI
- **Virtual Media** — mount/unmount ISO images on the BMC
- **BIOS / FRU** — view Field Replaceable Unit and firmware info

### UI
- Dark and light themes (toggle in header)
- Responsive sidebar with keyboard navigation
- Keyboard shortcuts for quick tab switching

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+1` | Dashboard |
| `Ctrl+2` | Power Control |
| `Ctrl+3` | Sensor Monitor |
| `Ctrl+4` | Serial Console |
| `Ctrl+5` | Virtual Media |
| `Ctrl+6` | Event Log |
| `Ctrl+7` | BIOS / FRU |
| `Ctrl+R` | Refresh current page |
| `Ctrl+L` | Connect / Disconnect |

## Download

Grab the latest installer from [Releases](https://github.com/felixfx2/ipmi-desktop-manager/releases):

- **Windows**: `IPMI Desktop Manager_x.x.x_x64-setup.exe` (NSIS) or `.msi`
- **Linux**: `.deb`, `.AppImage`, or `.rpm`
- **macOS**: `.dmg` or `.app.tar.gz`

## Build from Source

### Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| [Rust](https://rustup.rs/) | 1.77+ | Install via rustup |
| [Node.js](https://nodejs.org/) | 18+ | Only needed if adding a frontend build step |
| MSVC Build Tools | 2022+ | Windows only — [download](https://visualstudio.microsoft.com/visual-cpp-build-tools/) |

### Build

```bash
# Clone
git clone https://github.com/felixfx2/ipmi-desktop-manager.git
cd ipmi-desktop-manager

# Install Tauri CLI (if not already)
cargo install tauri-cli

# Dev mode (hot reload)
cargo tauri dev

# Production build (creates installer in src-tauri/target/release/bundle/)
cargo tauri build
```

On Windows, ensure MSVC environment is active before building:

```cmd
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
```

## Architecture

```
ipmi-desktop-manager/
├── src/                        # Frontend (vanilla HTML/CSS/JS)
│   ├── index.html              # App shell
│   ├── css/app.css             # All styles, dark/light themes
│   └── js/app.js               # SPA logic, Tauri IPC calls
├── src-tauri/                  # Backend (Rust)
│   ├── src/
│   │   ├── lib.rs              # Tauri builder, command registration
│   │   ├── commands/mod.rs     # All Tauri IPC command handlers
│   │   ├── ipmi/
│   │   │   ├── mod.rs          # IPMI 2.0 protocol (RAKP auth, raw UDP)
│   │   │   └── sol.rs          # Serial over LAN implementation
│   │   ├── redfish/mod.rs      # Redfish REST API client
│   │   └── keychain/mod.rs     # OS credential storage
│   ├── permissions/default.toml # Tauri v2 ACL permission definitions
│   ├── capabilities/default.json # IPC capability grants
│   ├── tauri.conf.json         # App config, bundler settings
│   └── Cargo.toml              # Rust dependencies
├── .gitignore
└── README.md
```

### Protocol Flow

```
Frontend (JS)  ──invoke()──>  Tauri Commands (Rust)
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
              Redfish Client  IPMI Client   Keychain
              (HTTPS REST)   (Raw UDP:623)  (OS Store)
```

1. On connect, tries Redfish first (faster, richer data)
2. Falls back to raw IPMI 2.0 if Redfish unavailable
3. Protocol mode (Auto / Redfish Only / IPMI Only) is user-configurable

## Configuration

All settings are stored locally:

| Setting | Location | Description |
|---------|----------|-------------|
| Credentials | OS Keychain | Encrypted by the OS — never stored in plaintext |
| Theme | localStorage | Dark / light preference |
| Protocol mode | In-memory | Per-session, resets on restart |

## Roadmap

- [ ] KVM / remote screen sharing (Phase 2 — research complete)
- [ ] Fan speed control
- [ ] LDAP/AD authentication support
- [ ] Multi-server management (save multiple BMC profiles)
- [ ] macOS and Linux builds
- [ ] Auto-update mechanism

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Push and open a Pull Request

## License

MIT
