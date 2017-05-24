api/credstore.pb.go: proto/credstore.proto
	mkdir -p api
	cd proto && protoc -I/usr/local/include -I. \
	 -I${GOPATH}/src \
	 -I${GOPATH}/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
	 --go_out=Mgoogle/api/annotations.proto=github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis/google/api,plugins=grpc:../api \
	 credstore.proto

run:
	go run main.go \
	  -listen=127.0.0.1:8008 \
		-logtostderr \
		-signing-key stash/signing.key \
		-config stash/config.yaml

.PHONY: run
