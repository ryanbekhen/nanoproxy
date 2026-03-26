FROM alpine:3.21
ARG TARGETPLATFORM
COPY --chmod=0755 $TARGETPLATFORM/nanoproxy /usr/bin/nanoproxy

ENV USER_STORE_PATH=/var/lib/nanoproxy/data.db

VOLUME ["/var/lib/nanoproxy"]

EXPOSE 1080
EXPOSE 8080
EXPOSE 9090

ENTRYPOINT ["nanoproxy"]