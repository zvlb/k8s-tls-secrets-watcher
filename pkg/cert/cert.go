package cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"time"
)

type CA struct {
	certificate *x509.Certificate
	key         crypto.PrivateKey
}

func GenerateCertificateAuthority() (s *CA, err error) {
	s = &CA{
		certificate: &x509.Certificate{
			SerialNumber: big.NewInt(2019),
			Subject: pkix.Name{
				Organization:  []string{"ZVLB"},
				Country:       []string{"CY"},
				Province:      []string{""},
				Locality:      []string{"Limassol"},
				StreetAddress: []string{"666, Best Street"},
				PostalCode:    []string{"6666"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		},
	}

	s.key, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	return
}

func (c CA) CACertificatePem() (b *bytes.Buffer, err error) {
	var crtBytes []byte

	switch key := c.key.(type) {
	case *rsa.PrivateKey:
		crtBytes, err = x509.CreateCertificate(rand.Reader, c.certificate, c.certificate, &key.PublicKey, key)
		if err != nil {
			return
		}
	case *ecdsa.PrivateKey:
		crtBytes, err = x509.CreateCertificate(rand.Reader, c.certificate, c.certificate, &key.PublicKey, key)
		if err != nil {
			return
		}
	default:
		err = ErrKeyNotSupportedFormat
		return
	}

	b = new(bytes.Buffer)
	err = pem.Encode(b, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crtBytes,
	})

	return
}

func GetCertificatesWithPrivateKeyFromBytes(certBytes, keyBytes []byte) ([]*x509.Certificate, crypto.PrivateKey, error) {
	pemCerts := bytes.SplitAfter(certBytes, []byte("-----END CERTIFICATE-----"))
	certs := []*x509.Certificate{}

	for _, pemCert := range pemCerts {
		// 10 it's mean \n
		if len(pemCert) != 0 && pemCert[0] != 10 {
			certificate, err := GetCertificateFromBytes(pemCert)
			if err != nil {
				return nil, nil, err
			}
			certs = append(certs, certificate)
		}
	}

	if len(certs) == 0 {
		return nil, nil, ErrCertNotFound
	}

	key, err := GetKeyFromBytes(keyBytes)
	if err != nil {
		return nil, nil, err
	}

	return certs, key, nil
}

func GetCertificateFromBytes(certBytes []byte) (*x509.Certificate, error) {
	var b *pem.Block

	b, _ = pem.Decode(certBytes)

	if b == nil {
		return nil, ErrFailedDecodeCert
	}

	return x509.ParseCertificate(b.Bytes)
}

func GetKeyFromBytes(keyBytes []byte) (crypto.PrivateKey, error) {
	if len(keyBytes) == 0 {
		return nil, ErrKeyNotFound
	}

	var b *pem.Block

	b, _ = pem.Decode(keyBytes)

	if b == nil {
		return nil, ErrFailedDecodeKey
	}

	keyParse, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		if strings.Contains(err.Error(), "use ParseECPrivateKey instead for this key format") {
			keyParse, err = x509.ParseECPrivateKey(b.Bytes)
			if err != nil {
				return nil, err
			}
			return keyParse, nil
		}
		if strings.Contains(err.Error(), "use ParsePKCS1PrivateKey instead for this key format") {
			keyParse, err = x509.ParsePKCS1PrivateKey(b.Bytes)
			if err != nil {
				return nil, err
			}
			return keyParse, nil
		}
		return nil, err
	}

	return keyParse, nil
}

func CertKeyEqual(cert *x509.Certificate, key crypto.PrivateKey) (bool, error) {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		p := key.Public().(*rsa.PublicKey)
		if p.N.Cmp(cert.PublicKey.(*rsa.PublicKey).N) == 0 {
			return true, nil
		}
		return false, nil
	case *ecdsa.PrivateKey:
		p := key.Public().(*ecdsa.PublicKey)
		if p.X.Cmp(cert.PublicKey.(*ecdsa.PublicKey).X) == 0 && p.Y.Cmp(cert.PublicKey.(*ecdsa.PublicKey).Y) == 0 {
			return true, nil
		}
		return false, nil
	}
	return false, ErrKeyNotSupportedFormat
}

func (c *CA) GenerateCertificate(opts CertificateOptions) (certificatePem *bytes.Buffer, certificateKey *bytes.Buffer, err error) {
	var certPrivKey *rsa.PrivateKey
	certPrivKey, err = rsa.GenerateKey(rand.Reader, 4096)

	if err != nil {
		return nil, nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"ZVLB"},
			Country:       []string{"CY"},
			Province:      []string{""},
			Locality:      []string{"Limassol"},
			StreetAddress: []string{"666, Best Street"},
			PostalCode:    []string{"6666"},
		},
		DNSNames:     opts.DNSNames(),
		NotBefore:    time.Now().AddDate(0, 0, -1),
		NotAfter:     opts.ExpirationDate(),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	var certBytes []byte
	certBytes, err = x509.CreateCertificate(rand.Reader, cert, c.certificate, &certPrivKey.PublicKey, c.key)

	if err != nil {
		return nil, nil, err
	}

	certificatePem = new(bytes.Buffer)
	err = pem.Encode(certificatePem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	if err != nil {
		return
	}

	certificateKey = new(bytes.Buffer)

	err = pem.Encode(certificateKey, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		return
	}

	return
}

func GetDomainsFromCertificate(cert *x509.Certificate) []string {
	return cert.DNSNames
}
