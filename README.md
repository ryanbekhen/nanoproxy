# NanoProxy

![coverage](https://raw.githubusercontent.com/ryanbekhen/nanoproxy/badges/.badges/master/coverage.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/ryanbekhen/nanoproxy?cache=v1)](https://goreportcard.com/report/github.com/vladopajic/go-test-coverage)

NanoProxy is a lightweight HTTP proxy server designed to provide basic proxying functionality. 
It supports handling HTTP requests and tunneling for HTTPS. NanoProxy is written in Go and built on top of Fiber.

> ⚠️ **Notice:** NanoProxy is currently in pre-production stage. While it provides essential proxying capabilities, 
> please be aware that it is still under active development. Full backward compatibility is not guaranteed until 
> reaching a stable release. We recommend caution when using NanoProxy for critical production applications. Make sure 
> to keep an eye on the changelog and be prepared for manual migration steps as the project evolves.

## Data Flow Through Proxy

NanoProxy acts as an intermediary between user requests and the destination server. When a user makes a request, 
NanoProxy forwards the request to the destination server. The destination server processes the request and responds 
back to NanoProxy, which then sends the response back to the user. This allows NanoProxy to intercept and manage 
network traffic effectively.

Here's how the data flows through the proxy:

```text
      Network          Proxy            Destination Server
    .---------.     .---------.       .-----------------.
--> |         | --> |         | ----> |                 |
    | Request |     | Forward | <---- |  Process &      |
<-- |         | <-- | Request |       |  Respond        |
    `---------'     `---------'       |                 |
                                      `-----------------'
```

This clear separation of responsibilities helps optimize network communication and enables various 
proxy-related functionalities.

## Features

- **Simple and minimalistic HTTP proxy server.** NanoProxy is designed with simplicity in mind, making it easy to set 
up and use for various purposes.
- **Handles both HTTP requests and tunneling (CONNECT) for HTTPS.** NanoProxy supports both HTTP requests and tunneling, 
allowing you to proxy regular HTTP requests as well as secure HTTPS connections.
- **Lightweight and easy to configure.** With a small footprint and straightforward configuration options, NanoProxy is 
a lightweight solution that can be quickly configured to suit your needs.

## Installation

You can easily install NanoProxy using your package manager by adding the official NanoProxy repository.

### Debian and Ubuntu

Add the NanoProxy repository to your sources list:

```shell
echo "deb [trusted=yes] https://repo.ryanbekhen.dev/apt/ /" | sudo tee /etc/apt/sources.list.d/ryanbekhen.list
```

Then, update the package list and install NanoProxy:

```shell
sudo apt update
sudo apt install nanoproxy
```

### Red Hat, CentOS, and Fedora

Add the NanoProxy repository configuration:

```shell
sudo tee /etc/yum.repos.d/ryanbekhen.repo <<EOF
[fury]
name=ryanbekhen
baseurl=https://repo.ryanbekhen.dev/yum/
enabled=1
gpgcheck=0
EOF
```

Now, you can install NanoProxy using yum:
```shell
sudo yum update
sudo yum install nanoproxy
```

## Usage

After installing NanoProxy using the provided packages (.deb or .rpm) or accessed it through the repository,
you can manage NanoProxy as a service using the system's service management tool (systemd). To enable NanoProxy to start 
automatically on system boot, run the following command:

To enable automatic startup on system boot, run:

```shell
sudo systemctl enable nanoproxy
```

To start the service, run:

```shell
sudo systemctl start nanoproxy
```

## Running on Docker

You can also run NanoProxy using Docker. To do so, you can use the following command:

```shell
docker run -p 8080:8080 ghcr.io/ryanbekhen/nanoproxy:latest
```

## Configuration

You can modify the behavior of NanoProxy by adjusting the command line flags when running the proxy. The available flags are:

- `-addr`: Proxy listen address (default: :8080).
- `-pem`: Path to the PEM file for TLS (HTTPS) support.
- `-key`: Path to the private key file for TLS.
- `-proto`: Proxy protocol `http` or `https`. If set to `https`, the `-pem` and `-key` flags must be set.
- `-timeout`: Timeout duration for tunneling connections (default: 15 seconds).
- `-auth`: Basic authentication credentials in the form of `username:password`.
- `-debug`: Enable debug mode.

You can set the configuration using environment variables. Create a file
at `/etc/nanoproxy/nanoproxy.env` and add the desired values:

```text
ADDR=:8080
PROTO=http
PEM=server.pem
KEY=server.key
TIMEOUT=15s
AUTH=user:pass
TZ=Asia/Jakarta
```

Modify these flags or environment variables according to your requirements.

## Testing

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
