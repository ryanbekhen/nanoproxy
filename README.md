# NanoProxy

NanoProxy is a lightweight HTTP proxy server designed to provide basic proxying functionality. 
It supports handling HTTP requests, tunneling, and follows redirects.

> ⚠️ **Notice:** NanoProxy is currently in pre-production stage. While it provides essential proxying capabilities, 
> please be aware that it is still under active development. Full backward compatibility is not guaranteed until 
> reaching a stable release. We recommend caution when using NanoProxy for critical production applications. Make sure 
> to keep an eye on the changelog and be prepared for manual migration steps as the project evolves.

## Features

- Simple and minimalistic HTTP proxy server.
- Handles both HTTP requests and tunneling (CONNECT) for HTTPS.
- Lightweight and easy to configure.

## Getting Started

### Installation

You have multiple options for installing NanoProxy:

#### 1. Download from GitHub Releases

You can download the latest release of NanoProxy from the 
[GitHub Releases page](https://github.com/ryanbekhen/nanoproxy/releases). Choose the appropriate installer for your 
operating system.

#### 2. Build from Source

1. Clone this repository: `git clone https://github.com/ryanbekhen/NanoProxy.git`
2. Navigate to the project directory: `cd NanoProxy`
3. Run the proxy server: `go build -o nanoproxy proxy.go`

### Usage

1. Run the proxy server: `./nanoproxy`
2. The proxy will start listening on the default address and port (:8080) and use default configuration values.

### Running on Docker

You can also run NanoProxy using Docker. To do so, you can use the following command:

```shell
docker run -p 8080:8080 ghcr.io/ryanbekhen/nanoproxy:latest
```

### Configuration

You can modify the behavior of NanoProxy by adjusting the command line flags when running the proxy. The available flags are:

- `-addr`: Proxy listen address (default: :8080).
- `-pem`: Path to the PEM file for TLS (HTTPS) support.
- `-key`: Path to the private key file for TLS.
- `-proto`: Proxy protocol `http` or `https`. If set to `https`, the `-pem` and `-key` flags must be set.
- `-timeout`: Timeout duration for tunneling connections (default: 15 seconds).

If you are installing NanoProxy locally, you can set the configuration using environment variables. Create a file
at `/etc/nanoproxy/nanoproxy.env` and add the desired values:

```text
ADDR=:8080
PROTO=http
PEM=server.pem
KEY=server.key
TIMEOUT=15s
```

Modify these flags or environment variables according to your requirements.

### Testing with cURL

To test the proxy using cURL, you can use the `-x` flag followed by the proxy URL. For example, to fetch the Google 
homepage using the proxy running on `localhost:8080`, use the following command:

```shell
curl -x localhost:8080 https://www.google.com
```

Replace localhost:8080 with the actual address and port where your NanoProxy instance is running. This command instructs 
cURL to use the specified proxy for the request, allowing you to see the request and response through the proxy server.

Remember that you can adjust the proxy address and port as needed based on your setup. This is a convenient way to 
verify that NanoProxy is correctly intercepting and forwarding the traffic.



## Contributions

Contributions are welcome! Feel free to open issues and submit pull requests.

## Security

If you discover any security related issues, please email i@ryanbekhen.dev instead of using the issue tracker.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
