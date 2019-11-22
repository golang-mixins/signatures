// Package p7s represents the interface signatures implementation.
// Implements signature parsing as PKCS#7 with content in ASN.1.
package v1

import (
	"github.com/golang-mixins/signatures"
	"github.com/mozilla-services/pkcs7"
	"golang.org/x/xerrors"
)

// Signatures defines the structure implements interfaces schedule.
// Using structure methods without initialization with the New constructor will lead to panic.
type Signatures struct{}

// Parse - parsing signatures into the structure according to the standards required by interface.
func (s *Signatures) Parse(data []byte) (*signatures.Signature, error) {
	sign, err := pkcs7.Parse(data)
	if err != nil {
		err = xerrors.Errorf("signature parsing error as 'PKCS #7': content does not match 'ASN.1' structure "+
			"format, more details: %w", err)
		return nil, err
	}

	return &signatures.Signature{
		Content:      data,
		Certificates: sign.Certificates,
	}, nil
}

// Ext - provides an extension for signature, according to the requirements of the interface.
func (s *Signatures) Ext() string {
	return ".p7s"
}

// New - constructor Signatures.
func New() *Signatures { return &Signatures{} }
