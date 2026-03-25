FROM alpine:3.21
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/nanoproxy /usr/bin

RUN mkdir -p /etc/nanoproxy

ENV USER_STORE_PATH=/etc/nanoproxy/data.db

EXPOSE 1080
EXPOSE 8080
EXPOSE 9090

ENTRYPOINT ["nanoproxy"]