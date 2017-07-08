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
	"crypto/x509"
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

// AuthServer implements CredStoreAuth service.
type AuthServer struct {
	signingKey *ecdsa.PrivateKey
	signer     jose.Signer
	config     *config.Config
}

type authServerTokenType struct{}

var authServerToken = authServerTokenType{}

// NewAuthServer returns a new AuthServer.
func NewAuthServer(signingKey *ecdsa.PrivateKey, config *config.Config) (*AuthServer, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES384, Key: signingKey},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{"typ": "JWT"},
		})
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT signer: %v", err)
	}

	return &AuthServer{signingKey: signingKey, signer: signer, config: config}, nil
}

// Auth takes in a static jwt (bundled into the binary) and returns a session
// jwt, useable for other RPCs with credstore.
func (s AuthServer) Auth(ctx context.Context, req *pb.AuthRequest) (*pb.AuthReply, error) {
	tok := ctx.Value(authServerToken).(jwt.AppToken)
	client := tok.Client

	if !s.config.FindClient(client) {
		glog.Errorf("client %s is not authorized to access this server", client)
		return nil, grpc.Errorf(codes.PermissionDenied, "client %s is not authorized to access this server", client)
	}

	authToken, err := jwt.BuildAuthToken(client)
	if err != nil {
		glog.Errorf("failed to serialize JWT token: %v", err)
		return nil, grpc.Errorf(codes.Internal, "failed to serialize JWT token: %v", err)
	}
	object, err := s.signer.Sign(authToken)
	if err != nil {
		glog.Errorf("failed to sign JWT payload: %v", err)
		return nil, grpc.Errorf(codes.Internal, "failed to sign JWT payload: %v", err)
	}

	serialized, err := object.CompactSerialize()
	if err != nil {
		glog.Errorf("failed to serialize short-form token: %v", err)
		return nil, grpc.Errorf(codes.Internal, "failed to serialize short-form token: %v", err)
	}

	repl := &pb.AuthReply{AuthJwt: serialized}

	return repl, nil
}

// SigningKey returns the currently used public key.
func (s AuthServer) SigningKey(context.Context, *pb.SigningKeyRequest) (*pb.SigningKeyReply, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(s.signingKey.Public())
	if err != nil {
		glog.Errorf("failed to marshal ec public key: %v", err)
		return nil, grpc.Errorf(codes.Internal, "failed to marshal ec public key: %v", err)
	}

	repl := &pb.SigningKeyReply{
		SigningKey: pubkeyBytes,
	}

	return repl, nil
}

// AuthServerInterceptor build inerceptor that verifies access to auth handler.
func AuthServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		_, ok := info.Server.(*AuthServer)
		if !ok {
			return handler(ctx, req)
		}

		jwtTokString := ctx.Value(client.TokenKey).([]byte)
		var jwtTok jwt.AppToken
		err := json.Unmarshal(jwtTokString, &jwtTok)
		if err != nil {
			glog.Errorf("cannot deserialize JWT token: %v", err)
			return nil, grpc.Errorf(codes.Unauthenticated, "cannot deserialize JWT token: %v", err)
		}

		if err := jwtTok.Verify(); err != nil {
			glog.Errorf("cannot verify JWT token: %v", err)
			return nil, grpc.Errorf(codes.Unauthenticated, "cannot verify JWT token: %v", err)
		}

		newCtx := context.WithValue(ctx, authServerToken, jwtTok)
		return handler(newCtx, req)
	}
}
