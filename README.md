# NanoProxy

![coverage](https://raw.githubusercontent.com/ryanbekhen/nanoproxy/badges/.badges/master/coverage.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/ryanbekhen/nanoproxy?cache=v1)](https://goreportcard.com/report/github.com/ryanbekhen/nanoproxy)

Note: This code includes modifications from the original go-socks5 project (https://github.com/armon/go-socks5)
Modifications have been made as part of maintenance for NanoProxy.
This version is licensed under the MIT license.

NanoProxy is a lightweight SOCKS5 proxy server written in Go. It is designed to be simple, minimalistic, and easy to
use.

> ⚠️ **Notice:** NanoProxy is currently in pre-production stage. While it provides essential proxying capabilities,
> please be aware that it is still under active development. Full backward compatibility is not guaranteed until
> reaching a stable release. We recommend caution when using NanoProxy for critical production applications. Make sure
> to keep an eye on the changelog and be prepared for manual migration steps as the project evolves.

## Data Flow Through Proxy

NanoProxy acts as a proxy server that forwards network traffic between the user and the destination server.
When a user makes a request, the request is sent to the proxy server. The proxy server then forwards the request to
the destination server. The destination server processes the request and responds back to the proxy server, which then
sends the response back to the user. This allows the proxy server to intercept and manage network traffic effectively.

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

This clear separation of responsibilities helps optimize network communication and enables various proxy-related
functionalities.

## Features

NanoProxy provides the following features:

- **SOCKS5 proxy server.** NanoProxy is a SOCKS5 proxy server that can be used to proxy network traffic for various
  applications.

## Installation

You can easily install NanoProxy using your package manager by adding the official NanoProxy repository.

### Debian and Ubuntu

Add the NanoProxy repository to your source list:

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

After installing NanoProxy using the provided packages (.deb or .rpm) or accessing it through the repository,
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

## Running on Terminal/Command Prompt

You can also run NanoProxy directly on your terminal/command prompt. To do so, you can use the following command:

```shell
nanoproxy
```

## Running on Docker

You can also run NanoProxy using Docker. To do so, you can use the following command:

```shell
docker run -p 1080:1080 ghcr.io/ryanbekhen/nanoproxy:latest
```

## Configuration

You can also set the configuration using environment variables. Create a file at `/etc/nanoproxy/nanoproxy` and add the
desired values:

```text
ADDR=:1080
NETWORK=tcp
TZ=Asia/Jakarta
CLIENT_TIMEOUT=10s
DNS_TIMEOUT=10s
CREDENTIALS=username:passwordHash
```

For the creation of the password hash, you can use the `htpasswd -nB username` command, but you need to install the
`apache2-utils` package first. To install the package, run the following command:

```shell
sudo apt install apache2-utils
```

Then, you can use the `htpasswd` command to generate the password hash:

```shell
htpasswd -nB username
```

This will prompt you to enter the password. After entering the password, the command will output the username and the
password hash. You can then use the output to set the `CREDENTIALS` environment variable.

The following table lists the available configuration options:

| Name           | Description                                           | Default Value |
|----------------|-------------------------------------------------------|---------------|
| ADDR           | The address to listen on.                             | `:1080`       |
| NETWORK        | The network to listen on. (tcp, tcp4, tcp6)           | `tcp`         |
| TZ             | The timezone to use.                                  | `Local`       |
| CLIENT_TIMEOUT | The timeout for connecting to the destination server. | `10s`         |
| DNS_TIMEOUT    | The timeout for DNS resolution.                       | `10s`         |
| CREDENTIALS    | The credentials to use for authentication.            | `""`          |

## Logging

NanoProxy logs all requests and responses to the standard output. You can use the `journalctl` command to view the logs:

```shell
journalctl -u nanoproxy
```

## Testing

To test the proxy using cURL, you can use the `-x` flag followed by the proxy URL. For example, to fetch the Google
homepage using the proxy running on `localhost:8080`, use the following command:

```shell
curl -x socks5://localhost:1080 https://google.com
```

Replace localhost:8080 with the actual address and port where your NanoProxy instance is running. This command instructs
cURL to use the specified proxy for the request, allowing you to see the request and response through the proxy server.

Remember that you can adjust the proxy address and port as needed based on your setup. This is a convenient way to
verify that NanoProxy is correctly intercepting and forwarding the traffic.

## Contributions

Contributions are welcome! Feel free to open issues and submit pull requests.

## Security

If you discover any security-related issues, please email i@ryanbekhen.dev instead of using the issue tracker.

## License

This project is licensed under the MIT License—see the [LICENSE](LICENSE) file for details.
