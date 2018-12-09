package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"

	"github.com/abhigyandwivedi/tls_workspace/eric-chang-tls-implementation/lib"
	"github.com/abhigyandwivedi/tls_workspace/eric-chang-tls-implementation/server/certs"
)

func main() {

	certs.Loader()
	ok := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hi"))
	}

	/***************
	//Gives the following error:
	//2018/12/09 16:20:38 Bad Request%!(EXTRA *url.Error=Get https://127.0.0.1:41999: x509: certificate signed by unknown authority)
	s := httptest.NewUnstartedServer(http.HandlerFunc(ok))
	s.TLS = &tls.Config{
		//	certs.RootTLSCert
		Certificates: []tls.Certificate{certs.RootTLSCert},
	}
	// make a HTTPS request to the server
	s.StartTLS()
	_, err := http.Get(s.URL)
	if err != nil {
		log.Fatalf("Bad Request", err)
	}
	s.Close()
	********************/

	/****
	Getting the Client to Trust the Server
	Rather than using a self-signed certificate, let’s create a setup
	that mimics a real situation where a certificate authority provides a
	organization with a cert for their website. To do this, we’ll pretend the
	rootCert we created before belongs to the certificate authority, and we’ll
	be attempting to create another certificate for our server.
	First things first, we’ll create a new key-pair and template.
	*****/
	serverAuthHandlerTest(ok)

}

func createServerAuthCertificate() (tls.Certificate, error) {

	serverPrivKey, serverCertTempl := lib.GenerateRootKeyPairAndCertTemplFixed(true)
	_, serverCertx509PEM, _ := lib.CreateCert(serverCertTempl, certs.RootStructure.RootCert, &serverPrivKey.PublicKey, certs.RootStructure.RootPrivateKey)
	serverPEMKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey),
	})
	return tls.X509KeyPair(serverCertx509PEM, serverPEMKey)

}
func serverAuthHandlerTest(handler http.HandlerFunc) {
	tlsServerCert, err := createServerAuthCertificate()
	if err != nil {
		log.Fatalf("Error Happened when creating TLS certificate for server:", err)
	}
	s := httptest.NewUnstartedServer(handler)
	s.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsServerCert},
	}
	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(certs.RootStructure.RootCertPEM)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: clientCertPool,
			},
		},
	}
	s.StartTLS()
	resp, err := client.Get(s.URL)
	if err != nil {
		log.Fatalf("could not make GET request: %v", err)
	}
	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Fatalf("could not dump response: %v", err)
	}
	fmt.Printf("%s\n", dump)

}
