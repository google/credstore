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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/golang/glog"
)

func main() {
	defer glog.Flush()

	privkey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		glog.Fatalf("failed to generate a keypair: %v", err)
	}

	privkeyBytes, err := x509.MarshalECPrivateKey(privkey)
	if err != nil {
		glog.Fatalf("failed to marshal ec key: %v", err)
	}

	err = pem.Encode(os.Stdout, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privkeyBytes,
	})
	if err != nil {
		glog.Fatalf("failed to encode ec key: %v", err)
	}

	pubkeyBytes, err := x509.MarshalPKIXPublicKey(privkey.Public())
	if err != nil {
		glog.Fatalf("failed to marshal ec public key: %v", err)
	}

	err = pem.Encode(os.Stdout, &pem.Block{Type: "EC PUBLIC KEY", Bytes: pubkeyBytes})
	if err != nil {
		glog.Fatalf("failed to encode ec public key: %v", err)
	}
}
