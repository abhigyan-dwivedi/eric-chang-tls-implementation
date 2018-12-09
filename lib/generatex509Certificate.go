package lib

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net"
	"time"
)

func CertTemplate() (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	serielNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serielNumber, err := rand.Int(rand.Reader, serielNumberLimit)
	if err != nil {
		return nil, errors.New("Error Happened while genreating certificates,failed to generate serial number:" + err.Error())
	}
	tmpl := x509.Certificate{
		SerialNumber: serielNumber,
		Subject: pkix.Name{
			Organization:       []string{"Abhigyan", "Inc"},
			OrganizationalUnit: []string{"DEV"},
		},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		BasicConstraintsValid: true,
	}
	return &tmpl, err
}

func GenerateRootKeyPairAndCertTempl() (*rsa.PrivateKey, *x509.Certificate) {
	rootkey, err := GenerateNewKeyPair(2048)
	if err != nil {
		log.Fatalf("Error Happened while gernerating root keys,generating random key:%v", err)

	}
	rootCertTempl, err := CertTemplate()
	if err != nil {
		log.Fatalf("Error Happened while gernerating root certificate template:%v", err)

	}
	rootCertTempl.IsCA = true
	rootCertTempl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	rootCertTempl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} //Faulty Step
	rootCertTempl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	return rootkey, rootCertTempl
}

func GenerateRootKeyPairAndCertTemplFixed(isServer bool) (*rsa.PrivateKey, *x509.Certificate) {
	rootkey, err := GenerateNewKeyPair(2048)
	if err != nil {
		log.Fatalf("Error Happened while gernerating root keys,generating random key:%v", err)

	}
	rootCertTempl, err := CertTemplate()
	if err != nil {
		log.Fatalf("Error Happened while gernerating root certificate template:%v", err)

	}
	rootCertTempl.IsCA = true
	rootCertTempl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	//rootCertTempl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} //Faulty Step
	if isServer {
		rootCertTempl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		rootCertTempl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	rootCertTempl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	return rootkey, rootCertTempl
}

func CreateCert(template, parent *x509.Certificate, pub *rsa.PublicKey, parentPrivKey *rsa.PrivateKey) (cert *x509.Certificate, certPEM []byte, err error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPrivKey)
	if err != nil {
		return
	}
	// parse the resulting certificate so we can use it again
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	// PEM encode the certificate (this is a standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)
	return
}
