# Nancy API Debugger

Nancy API Debugger provides desktop and command-line clients for inspecting HTTP requests and their DNS, connection, TLS, header, and body details.

## Requirements

- Rust 1.88 or newer
- A graphical X11 or Wayland desktop session
- Working OpenGL support through EGL or GLX

### Ubuntu 26.04

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

Build the command-line client:

```sh
cargo build --locked --bin nancywebdebug-cli
```

Its syntax is:

```text
nancywebdebug-cli [OPTIONS] <URL>
```

For example:

```sh
nancywebdebug-cli https://example.com
nancywebdebug-cli --protocol http2 --no-follow-redirects https://example.com
nancywebdebug-cli --fingerprint-server https://example.com
nancywebdebug-cli -X POST -H "Content-Type: application/json" --body-file request.json https://example.com/api
```

Available request options are `-X, --method`, repeatable `-H, --header`, `--body-file`, `--protocol auto|http1.1|http2|http3`, `--no-follow-redirects`, and `--fingerprint-server`. Redirects are followed by default. The report includes every redirect hop and all captured diagnostic stages. Press Ctrl+C to cancel an active diagnostic.

Server fingerprinting is disabled by default. On Ubuntu, install Nmap with `sudo apt install nmap`, then run the GUI or CLI as root to permit its SYN scan. The scan probes every TCP port, performs service and OS detection, runs selected default or safe NSE scripts, and generates substantially more traffic than a normal request. Each distinct redirect origin is scanned at the remote IP selected by the connection diagnostics. On shared hosts, CDNs, load balancers, and shared IP addresses, the detected service may not belong exclusively to the requested hostname. Scanning can trigger network monitoring, rate limiting, or blocking even with the excluded intrusive script categories.

Linux TLS verification uses the system CA certificates. Keep the `ca-certificates` package and its trust store current. DNS resolution depends on a valid `/etc/resolv.conf`. HTTP/3 uses QUIC and requires outbound UDP access, normally to the destination's HTTPS port. Firewalls or networks that block UDP can prevent HTTP/3 while HTTP/1.1 and HTTP/2 continue to work over TCP.

The desktop application must be launched from an X11 or Wayland graphical session with functional OpenGL/EGL/GLX drivers. The command-line client can run headlessly.

## Windows

Install Rust 1.88 or newer and the Microsoft C++ Build Tools, then run:

```powershell
cargo run --locked
```
