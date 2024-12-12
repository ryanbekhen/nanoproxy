FROM busybox:1.36.1-glibc

COPY nanoproxy /usr/bin/nanoproxy
EXPOSE 1080
EXPOSE 8080

ENTRYPOINT ["nanoproxy"]