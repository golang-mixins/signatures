// Package p7s represents the interface signatures implementation.
// Implements signature parsing as PKCS#7 with content in ASN.1.
package v1

import (
	"encoding/base64"
	"encoding/pem"

	"github.com/golang-mixins/pkcs7"
	"github.com/golang-mixins/signatures"
	"golang.org/x/xerrors"
)

// Signatures defines the structure implements interfaces schedule.
// Using structure methods without initialization with the New constructor will lead to panic.
type Signatures struct{}

// Parse - parsing signatures into the structure according to the standards required by interface.
func (s *Signatures) Parse(data []byte) (signatures.Signature, error) {
	sign, err := pkcs7.Parse(data)
	if err != nil {
		err = xerrors.Errorf("signature parsing error as 'PKCS #7': content does not match 'ASN.1' structure "+
			"format, more details: %w", err)
		return signatures.Signature{}, err
	}

	return signatures.Signature{
		Content:      data,
		Certificates: sign.Certificates,
	}, nil
}

// Extract - extractes and parses the signature as BASE64 or PEM or DER, providing the result or an error.
func (s *Signatures) Extract(data []byte) (signatures.Signature, error) {
	// attempt to match with PEM, if successful - sent for parsing as PEM.
	block, _ := pem.Decode(data)
	if block != nil {
		return s.Parse(block.Bytes)
	}

	// attempt to match with BASE64, if successful - sent for parsing as BASE64.
	encBASE64 := base64.StdEncoding
	bufBASE64 := make([]byte, encBASE64.DecodedLen(len(data)))
	n, err := encBASE64.Decode(bufBASE64, data)
	if err == nil {
		return s.Parse(bufBASE64[:n])
	}

	// by default, parsed to DER
	return s.Parse(data)
}

// Ext - provides an extension for signature, according to the requirements of the interface.
func (s *Signatures) Ext() string {
	return ".p7s"
}

// New - constructor Signatures.
func New() *Signatures { return &Signatures{} }
