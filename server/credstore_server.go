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

package server

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	pb "github.com/google/credstore/api"
	"github.com/google/credstore/client"
	"github.com/google/credstore/config"
	"github.com/google/credstore/jwt"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	jose "gopkg.in/square/go-jose.v2"
)

// CredStoreServer implements CredStore service.
type CredStoreServer struct {
	signingKey *ecdsa.PrivateKey
	signer     jose.Signer
	config     *config.Config
}

type credStoreServerTokenType struct{}

var credStoreServerToken = credStoreServerTokenType{}

// NewCredStoreServer returns a new CredStoreServer.
func NewCredStoreServer(signingKey *ecdsa.PrivateKey, config *config.Config) (*CredStoreServer, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES384, Key: signingKey},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{"typ": "JWT"},
		})
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT signer: %v", err)
	}

	return &CredStoreServer{signingKey: signingKey, signer: signer, config: config}, nil
}

// GetToken provides a JWT token for remote endpoint based on its DNS name.
func (s CredStoreServer) GetToken(ctx context.Context, req *pb.GetTokenRequest) (*pb.GetTokenReply, error) {
	tok := ctx.Value(credStoreServerToken).(jwt.AuthToken)
	client := tok.Client

	if !s.config.FindClient(client) {
		glog.Errorf("client %s is not authorized to access this server", client)
		return nil, grpc.Errorf(codes.PermissionDenied, "client %s is not authorized to access this server", client)
	}

	scopeName := s.config.FindAuthorization(client, req.GetTarget())
	if scopeName == "" {
		glog.Errorf("client %s doesn't have a scope for %s", client, req.GetTarget())
		return nil, grpc.Errorf(codes.PermissionDenied, "client %s doesn't have a scope for %s", client, req.GetTarget())
	}

	scope := s.config.FindScope(scopeName)
	if scope == nil {
		glog.Errorf("client %s requested scope %s for %s, but no such scope is available", client, scopeName, req.GetTarget())
		return nil, grpc.Errorf(codes.Internal, "client %s requested scope %s for %s, but no such scope is available", client, scopeName, req.GetTarget())
	}

	rpcToken, err := jwt.BuildRPCToken(client, scope.Service, scope.Method)
	if err != nil {
		glog.Errorf("failed to serialize JWT token: %v", err)
		return nil, grpc.Errorf(codes.Internal, "failed to serialize JWT token: %v", err)
	}
	object, err := s.signer.Sign(rpcToken)
	if err != nil {
		glog.Errorf("failed to sign JWT payload: %v", err)
		return nil, grpc.Errorf(codes.Internal, "failed to sign JWT payload: %v", err)
	}
	serialized, err := object.CompactSerialize()
	if err != nil {
		glog.Errorf("failed to serialize short-form token: %v", err)
		return nil, grpc.Errorf(codes.Internal, "failed to serialize short-form token: %v", err)
	}

	repl := &pb.GetTokenReply{SessionJwt: serialized}

	return repl, nil
}

// CredStoreServerInterceptor build inerceptor that verifies access to auth handler.
func CredStoreServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		_, ok := info.Server.(*CredStoreServer)
		if !ok {
			return handler(ctx, req)
		}

		jwtTokString := ctx.Value(client.TokenKey).([]byte)
		var jwtTok jwt.AuthToken
		err := json.Unmarshal(jwtTokString, &jwtTok)
		if err != nil {
			glog.Errorf("cannot deserialize JWT token: %v", err)
			return nil, grpc.Errorf(codes.Unauthenticated, "cannot deserialize JWT token: %v", err)
		}

		if err := jwtTok.Verify(); err != nil {
			glog.Errorf("cannot verify JWT token: %v", err)
			return nil, grpc.Errorf(codes.Unauthenticated, "cannot verify JWT token: %v", err)
		}

		newCtx := context.WithValue(ctx, credStoreServerToken, jwtTok)
		return handler(newCtx, req)
	}
}
