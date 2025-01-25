FROM alpine:3

COPY nanoproxy /usr/bin/nanoproxy
EXPOSE 1080
EXPOSE 8080

ENTRYPOINT ["nanoproxy"]