FROM busybox:1.36.1-glibc

WORKDIR /root
COPY nanoproxy /usr/local/bin/nanoproxy

ENTRYPOINT ["nanoproxy"]