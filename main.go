/*

Copyright 2017 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package main

import (
	"flag"

	pb "github.com/google/credstore/api"
	"github.com/google/credstore/client"
	"github.com/google/credstore/config"
	"github.com/google/credstore/server"
	"github.com/google/go-microservice-helpers/pki"
	mlpserver "github.com/google/go-microservice-helpers/server"
	"github.com/google/go-microservice-helpers/tracing"
	"github.com/golang/glog"
	"github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/grpc-opentracing/go/otgrpc"
	opentracing "github.com/opentracing/opentracing-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	configFile     = flag.String("config", "", "path to a config file")
	signingKeyFile = flag.String("signing-key", "", "path to a signing private key")
)

func main() {
	flag.Parse()
	defer glog.Flush()

	err := tracing.InitTracer(*mlpserver.ListenAddress, "credstore")
	if err != nil {
		glog.Fatalf("failed to init tracing interface: %v", err)
	}

	signingKey, err := pki.LoadECKeyFromFile(*signingKeyFile)
	if err != nil {
		glog.Fatalf("failed to load signing key file: %v", err)
	}

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		glog.Fatalf("failed to load config: %v", err)
	}

	authSvr, err := server.NewAuthServer(signingKey, cfg)
	if err != nil {
		glog.Fatalf("failed to create auth server: %v", err)
	}

	credServer, err := server.NewCredStoreServer(signingKey, cfg)
	if err != nil {
		glog.Fatalf("failed to create cred store server: %v", err)
	}

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			otgrpc.OpenTracingServerInterceptor(opentracing.GlobalTracer()),
			client.CredStoreTokenInterceptor(signingKey.Public()),
			server.CredStoreServerInterceptor(),
			server.AuthServerInterceptor(),
		)))
	pb.RegisterCredStoreAuthServer(grpcServer, authSvr)
	pb.RegisterCredStoreServer(grpcServer, credServer)
	reflection.Register(grpcServer)

	err = mlpserver.ListenAndServe(grpcServer, nil)
	if err != nil {
		glog.Fatalf("failed to serve: %v", err)
	}
}
