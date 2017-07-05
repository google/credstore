FROM golang:alpine as builder
RUN apk --update add git
RUN go get -v github.com/google/credstore
RUN go get -v github.com/google/credstore/cmd/credstore-keygen
RUN go get -v github.com/google/credstore/cmd/credstore-tokengen

FROM alpine:latest
COPY --from=builder /go/bin/credstore /go/bin/credstore-keygen /go/bin/credstore-tokengen /bin/
CMD ["/bin/credstore", "-listen=0.0.0.0:8000", "-logtostderr", "-signing-key", "data/signing.key", "-config", "data/config.yaml"]
