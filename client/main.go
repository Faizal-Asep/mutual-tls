package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

type Dialer func(network, addr string) (net.Conn, error)

var cert tls.Certificate
var caCertPool *x509.CertPool

func init() {
	var err error
	cert, err = tls.LoadX509KeyPair("../cert/client-cert.pem", "../cert/client-key.pem")
	if err != nil {
		log.Fatal(err)
	}
	// Create a CA certificate pool and add cert.pem to it
	caCert, err := os.ReadFile("../cert/ca-cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool = x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
}

func makeDialer(fingerprint [32]byte, skipCAVerification bool) Dialer {
	return func(network, addr string) (net.Conn, error) {
		// Read the key pair to create certificate

		c, err := tls.Dial(network, addr, &tls.Config{
			RootCAs:            caCertPool,
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: skipCAVerification,
		})

		if err != nil {
			return c, err
		}
		connstate := c.ConnectionState()
		// fmt.Println("keyPinValid")
		keyPinValid := false
		for _, peercert := range connstate.PeerCertificates {
			der, err := x509.MarshalPKIXPublicKey(peercert.PublicKey)
			hash := sha256.Sum256(der)
			// log.Println(peercert.Issuer)
			// log.Printf("%#v", hash)
			if err != nil {
				log.Fatal(err)
			}
			if bytes.Equal(hash[0:], fingerprint[0:]) {
				keyPinValid = true
			}
		}

		if !keyPinValid {
			return c, errors.New(" Pinned Key not found")
		}
		return c, nil
	}
}

func main() {
	start := time.Now()
	// Create a HTTPS client and supply the created CA pool and certificate
	fingerprint := [32]byte{0xbf, 0x2c, 0x5f, 0xa1, 0xe3, 0xc6, 0x96, 0xec, 0xf7, 0xa, 0x47, 0x97, 0xf6, 0x6c, 0x23, 0x9c, 0x82, 0x92, 0xc6, 0x74, 0x59, 0x6c, 0x96, 0x11, 0xed, 0xb4, 0x9f, 0x5e, 0xe5, 0x3e, 0x5a, 0xe6}

	// fmt.Println(base64.StdEncoding.EncodeToString(fingerprint[0:]))
	client := &http.Client{
		Transport: &http.Transport{
			DialTLS: makeDialer(fingerprint, false),
		},
	}

	r, err := client.Get("https://localhost:8080/status")
	if err != nil {
		log.Fatal(err)
	}
	// Read the response body
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}
	// Print the response body to stdout
	fmt.Printf("%s\n", body)
	fmt.Println("Duration : ", time.Since(start))
}
