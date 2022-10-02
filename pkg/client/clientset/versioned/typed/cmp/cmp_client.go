package cmp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type ClientInterface interface {
	GetCertificate(*x509.Certificate, *x509.Certificate, crypto.PublicKey, interface{}) ([]byte, *x509.Certificate, error)
}

type Client struct {
	server string
}

func New(server string) ClientInterface {
	fmt.Println("## Initialized server", server)
	return &Client{
		server: server,
	}
}

func (c *Client) GetCertificate(template *x509.Certificate, issuerCert *x509.Certificate, publicKey crypto.PublicKey, signerKey interface{}) ([]byte, *x509.Certificate, error) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuerCert, publicKey, signerKey)

	if err != nil {
		return nil, nil, fmt.Errorf("error creating x509 certificate: %s", err.Error())
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding DER certificate bytes: %s", err.Error())
	}

	pemBytes := bytes.NewBuffer([]byte{})
	err = pem.Encode(pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return nil, nil, fmt.Errorf("error encoding certificate PEM: %s", err.Error())
	}

	return pemBytes.Bytes(), cert, err
}
