# NanoProxy

NanoProxy is a lightweight HTTP proxy server designed to provide basic proxying functionality. It supports handling HTTP requests, tunneling, and follows redirects.

## Features

- Simple and minimalistic HTTP proxy server.
- Handles both HTTP requests and tunneling (CONNECT) for HTTPS.
- Lightweight and easy to configure.

## Getting Started

### Installation

1. Clone this repository: `git clone https://github.com/ryanbekhen/NanoProxy.git`
2. Navigate to the project directory: `cd NanoProxy`

### Usage

1. Run the proxy server: `go run proxy.go`
2. The proxy will start listening on the default address and port (:8080) and use default configuration values.

### Configuration

You can modify the behavior of NanoProxy by adjusting the command line flags when running the proxy. The available flags are:

- `-addr`: Proxy listen address (default: :8080).
- `-pem`: Path to the PEM file for TLS (HTTPS) support.
- `-key`: Path to the private key file for TLS.
- `-proto`: Proxy protocol (http or https).
- `-timeout`: Timeout duration for tunneling connections (default: 15 seconds).

Modify these flags according to your requirements.

## Contributions

Contributions are welcome! Feel free to open issues and submit pull requests.

## Security

If you discover any security related issues, please email i@ryanbekhen.dev instead of using the issue tracker.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
