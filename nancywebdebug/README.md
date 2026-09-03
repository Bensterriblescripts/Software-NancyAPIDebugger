# Nancy API Debugger

Nancy API Debugger is a desktop application for inspecting HTTP requests and their DNS, connection, TLS, header, and body details.

## Requirements

- Rust 1.88 or newer
- A graphical X11 or Wayland desktop session
- Working OpenGL support through EGL or GLX

### Ubuntu 24.04

Install the required build and runtime development packages:

```sh
sudo apt update
sudo apt install build-essential cmake pkg-config ca-certificates libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libwebkit2gtk-4.1-dev
```

Install Rust with rustup:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Build and run the application from the repository root:

```sh
cargo run --locked
```

Linux TLS verification uses the system CA certificates. Keep the `ca-certificates` package and its trust store current. DNS resolution depends on a valid `/etc/resolv.conf`. HTTP/3 uses QUIC and requires outbound UDP access, normally to the destination's HTTPS port. Firewalls or networks that block UDP can prevent HTTP/3 while HTTP/1.1 and HTTP/2 continue to work over TCP.

The application must be launched from an X11 or Wayland graphical session with functional OpenGL/EGL/GLX drivers. Headless operation is not supported.

## Windows

Install Rust 1.88 or newer and the Microsoft C++ Build Tools, then run:

```powershell
cargo run --locked
```
