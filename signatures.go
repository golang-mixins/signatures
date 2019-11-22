// Package signatures presents interface (and its implementation sets) of a signatures.
package signatures

import (
	"crypto/x509"
)

// Signature typifies signature.
type Signature struct {
	// Content - signature content.
	Content []byte
	// Certificates - signature certificates.
	Certificates []*x509.Certificate
}

// SignatureParser provides signature parsing interface.
type SignatureParser interface {
	// Parse - parsing signatures into the structure according to the standards required by interface.
	Parse(data []byte) (*Signature, error)
	// Ext - provides an extension for signature, according to the requirements of the interface.
	Ext() string
}
