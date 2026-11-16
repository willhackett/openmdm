// Package applecerts embeds the two public Apple certificates that go at the
// end of a push certificate request's chain: the WWDR G3 intermediate and the
// Apple root. Both were downloaded once from Apple
// (https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer and
// http://www.apple.com/appleca/AppleIncRootCertificate.cer), converted to PEM
// and checked (see applecerts_test.go) before being committed.
package applecerts

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
)

//go:embed AppleWWDRCAG3.pem
var wwdrPEM []byte

//go:embed AppleIncRootCertificate.pem
var rootPEM []byte

// WWDRG3PEM is the Apple Worldwide Developer Relations G3 intermediate.
func WWDRG3PEM() []byte { return append([]byte(nil), wwdrPEM...) }

// RootPEM is the Apple Root CA.
func RootPEM() []byte { return append([]byte(nil), rootPEM...) }

func parse(p []byte) *x509.Certificate {
	blk, _ := pem.Decode(p)
	if blk == nil {
		panic("applecerts: embedded certificate is not PEM")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		panic("applecerts: " + err.Error())
	}
	return c
}

// WWDRG3 returns the parsed intermediate.
func WWDRG3() *x509.Certificate { return parse(wwdrPEM) }

// Root returns the parsed root.
func Root() *x509.Certificate { return parse(rootPEM) }
