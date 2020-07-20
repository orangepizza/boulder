package signer2

//throw eventhing in and see what's really needed
import (

	//	"context"
	"crypto"
	//	"crypto/ecdsa"
	"crypto/rand"
	//	"crypto/rsa"
	//	"crypto/sha256"
	"crypto/x509"

	//	"encoding/hex"
	//	"encoding/json"
	//	"encoding/pem"
	//	"errors"
	"fmt"
	"math/big"

	//	"strings"
	"time"
)

// IssuanceRequest call function with this
type IssuanceRequest struct {
	PublicKey          []byte
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	SignatureAlgorithm x509.SignatureAlgorithm

	Serial *big.Int

	DNSNames []string
	// IPAddresses []net.IP

	IncludeMustStaple bool
	IncludeCTPoison   bool
	IncludeSCTList    []byte
}

// Signer have, ca cert, actual signer for it, and allowed types
type Signer struct {
	issuer  *x509.Certificate
	signer  crypto.Signer
	profile struct {
		allowedKeyTypes            map[x509.PublicKeyAlgorithm]bool
		allowedSignatureAlgorithms map[x509.SignatureAlgorithm]bool

		allowDNSNames bool
		// allowIPAddresses bool

		allowMustStaple bool
		allowCTPoison   bool
		allowSCTList    bool

		// -----
		keyUsage    x509.KeyUsage
		extKeyUsage []x509.ExtKeyUsage
		ocspURL     string
		crlURL      string
		issuerURL   string
		//		policies       []PolicyInformation
		validityPeriod time.Duration // could also be set in IssuanceRequest with a min/max bound in profile
		// ----- or -----
		template *x509.Certificate
		// -----
	}
}

//Issue will sign precert
func (s Signer) Issue(req IssuanceRequest) ([]byte, error) {
	//is request's keyType allowed to sign?
	if !s.profile.allowedKeyTypes[req.PublicKeyAlgorithm] {
		return nil, fmt.Errorf("Signer doesn't allow request's keytype %s", req.PublicKeyAlgorithm.String())
	}
	if !s.profile.allowedSignatureAlgorithms[req.SignatureAlgorithm] {
		return nil, fmt.Errorf("Singer will not sign with algorithm %s", req.SignatureAlgorithm.String())
	}
	//now create empty cert template
	var template x509.Certificate
	//filling signer setted configs
	template.KeyUsage = s.profile.keyUsage
	template.ExtKeyUsage = s.profile.extKeyUsage
	template.OCSPServer = []string{s.profile.ocspURL}
	template.Issuer = s.issuer.Subject //signer's subject is cert's issuer
	template.IssuingCertificateURL = []string{s.profile.issuerURL}
	template.CRLDistributionPoints = []string{s.profile.crlURL}

	//template/s serial number is request provided or randomly choese
	//if abs of bigint is this mall it's prob
	if req.Serial.CmpAbs(big.NewInt(0)) == 0 {
		//if there is no serial number request we make 160bit (note longer then normal useage)
		const randBits = 160
		serialBytes := make([]byte, randBits/8+1)
		_, err := rand.Read(serialBytes[1:])
		if err != nil {
			err = fmt.Errorf("failed to generate serial: %s", err)
			return nil, err
		}
		template.SerialNumber.SetBytes(serialBytes)

	} else {
		template.SerialNumber.Set(req.Serial)
	}

	//if all check works really sign
	return x509.CreateCertificate(rand.Reader, &template, s.issuer, req.PublicKey, s.signer.Sign)
}
