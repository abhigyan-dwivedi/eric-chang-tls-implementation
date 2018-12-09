package certs

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/abhigyandwivedi/tls_workspace/eric-chang-tls-implementation/lib"
)

type Root struct {
	RootCert       *x509.Certificate
	RootCertPEM    []byte
	RootPrivateKey *rsa.PrivateKey
	RootKeyPEM     []byte
	RootTLSCert    tls.Certificate
}

var RootStructure *Root

func init() {
	RootStructure = &Root{}

	rootPrivateKey, rootCertTempl := lib.GenerateRootKeyPairAndCertTempl()
	RootStructure.RootPrivateKey = rootPrivateKey

	rootCert, rootCertPEM, err := lib.CreateCert(rootCertTempl, rootCertTempl, &RootStructure.RootPrivateKey.PublicKey, RootStructure.RootPrivateKey)

	RootStructure.RootCert = rootCert
	RootStructure.RootCertPEM = rootCertPEM

	if err != nil {
		log.Fatalf("Error happened while creating certificate:%v", err)
	}

	//PEM encode the root private key:
	RootStructure.RootKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(RootStructure.RootPrivateKey),
	})
	// Create a TLS cert using the private key and certificate
	RootStructure.RootTLSCert, err = tls.X509KeyPair(RootStructure.RootCertPEM, RootStructure.RootKeyPEM)

	if err != nil {
		log.Fatalf("invalid key pair: %v", err)
	}

}

func KeysStatus() {
	fmt.Println(RootStructure)
}

func Loader() {
	KeysStatus()
	fmt.Println("Certs Generated and Loaded")
}
