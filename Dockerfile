FROM alpine:latest

RUN set -ex; \
    apk add --no-cache --no-progress --virtual .build-deps git go musl-dev; \
    env GOPATH=/go go get -v github.com/google/credstore; \
    install -t /bin /go/bin/credstore; \
    rm -rf /go; \
    apk --no-progress del .build-deps

CMD ["/bin/credstore", "-listen=0.0.0.0:8000", "-logtostderr", "-signing-key", "data/signing.key", "-config", "data/config.yaml"]
