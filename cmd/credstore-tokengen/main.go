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
	"fmt"

	"github.com/google/credstore/jwt"
	"github.com/google/go-microservice-helpers/pki"

	"github.com/golang/glog"
	jose "gopkg.in/square/go-jose.v2"
)

var (
	clientName     = flag.String("client", "", "client name")
	signingKeyFile = flag.String("signing-key", "", "path to a signing private key")
	longFormTok    = flag.Bool("long", false, "generate long form token")
)

func main() {
	flag.Parse()
	defer glog.Flush()

	if *clientName == "" {
		glog.Fatalf("client name not specified")
	}

	if *signingKeyFile == "" {
		glog.Fatalf("signing key file not specified")
	}

	signingKey, err := pki.LoadECKeyFromFile(*signingKeyFile)
	if err != nil {
		glog.Fatalf("failed to load signing key file: %v", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES384, Key: signingKey},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{"typ": "JWT"},
		})
	if err != nil {
		glog.Fatalf("failed to create JWT signer: %v", err)
	}

	payload, err := jwt.BuildAppToken(*clientName)
	if err != nil {
		glog.Fatalf("failed to create JWT token: %v", err)
	}

	object, err := signer.Sign(payload)
	if err != nil {
		glog.Fatalf("failed to sign JWT payload: %v", err)
	}

	var serialized string
	if *longFormTok {
		serialized = object.FullSerialize()
	} else {
		serialized, err = object.CompactSerialize()
		if err != nil {
			glog.Fatalf("failed to serialize short-form token: %v", err)
		}
	}
	fmt.Println(serialized)
}
