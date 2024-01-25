package cache

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/zvlb/k8s-tls-secrets-watcher/pkg/cert"
)

type Cache interface {
	AddOrUpgrade(name, namespace string, certBytes, keyBytes []byte)
	Delete(name, namespace string)
	Get(name, namespace string) (CertData, error)
	GetAll() map[string]CertData
}

type CertData struct {
	// Name - name of secret
	Name string `json:"name"`

	// NameSpace - namespace of secret
	NameSpace string `json:"namespace"`

	Certificates []*x509.Certificate `json:"certificate"`

	// Collect from certificate for fast search
	CertificateIssuerOrg []string `json:"certificate_issuer_org"`

	// ExpireDate - unix timestamp
	ExpireDate int64 `json:"expire_date"`

	// Domains - list of domains in certificate
	Domains []string `json:"domains"`

	// CertKeyEqual - true if certificate and key equal
	CertKeyEqual bool `json:"cert_key_equal"`

	// SiteCertMatch - true if site certificate match with certificate in cache
	SiteCertMatch []SiteCertMatch `json:"site_cert_match"`

	Error error `json:"error"`
}

type SiteCertMatch struct {
	Domain  string `json:"domain"`
	Match   bool   `json:"match"`
	Message string `json:"message"`
}

var (
	ErrCertNotFound = errors.New("certificate not found in cache")
	// ErrCertParse     = errors.New("certificate parse error")
	// ErrKeyNotFound   = errors.New("key not found")
	// ErrCartKeyEqual  = errors.New("certificate and key not equal")
	// ErrSiteCertMatch = errors.New("site certificate doesent match with certificate in cache")

	MsgCannotCheckWildcartDomain = "can't check wildcard domain"
	MsgCannotGetDomain           = "can't get domain information"
)

func GetCertData(
	name, namespace string,
	certBytes, keyBytes []byte,
) CertData {
	certData := CertData{
		Name:      name,
		NameSpace: namespace,
	}

	// Get certificates and key
	certs, key, err := cert.GetCertificatesWithPrivateKeyFromBytes(certBytes, keyBytes)
	if err != nil {
		certData.Error = err
		return certData
	}

	certData.Certificates = certs

	// Get CertificateIssuerOrg
	// TODO: Find certificate issuer org from cert (non ca/root)
	for _, c := range certs {
		if c.IsCA {
			continue
		}
		certData.CertificateIssuerOrg = c.Issuer.Organization
	}

	// Get ExpireDate
	certData.ExpireDate = getExpireDate(certs)

	// Get Domains
	certData.Domains = getCertDomains(certs)

	// Check Certificates and Key equal
	for _, c := range certs {
		equal, err := cert.CertKeyEqual(c, key)
		if err != nil {
			certData.Error = err
			return certData
		}

		if equal {
			certData.CertKeyEqual = true
			break
		}
	}

	// Check SiteCertMatch
	siteCertMatch, err := checkSiteCertMatch(certs, certData.Domains)
	if err != nil {
		certData.Error = err
		return certData
	}
	certData.SiteCertMatch = siteCertMatch

	return certData

}

func getExpireDate(certs []*x509.Certificate) int64 {
	var expired int64
	for _, c := range certs {
		if c.NotAfter.Unix() < expired || expired == 0 {
			expired = c.NotAfter.Unix()
		}
	}
	return expired
}

func getCertDomains(certs []*x509.Certificate) []string {
	var domains []string
	for _, c := range certs {
		domains = append(domains, cert.GetDomainsFromCertificate(c)...)
	}
	return domains
}

func checkSiteCertMatch(certs []*x509.Certificate, domains []string) ([]SiteCertMatch, error) {
	result := make([]SiteCertMatch, 0)

C1:
	for _, d := range domains {
		if strings.Contains(d, "*") {
			result = append(result, SiteCertMatch{
				Domain:  d,
				Match:   false,
				Message: MsgCannotCheckWildcartDomain,
			})
			continue C1
		}

		conn, err := tls.Dial("tcp", fmt.Sprintf("%v:443", d), &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			result = append(result, SiteCertMatch{
				Domain:  d,
				Match:   false,
				Message: fmt.Sprintf("%v. Error: %v", MsgCannotGetDomain, err.Error()),
			})
			continue C1
		}
		defer conn.Close()

		siteCerts := conn.ConnectionState().PeerCertificates

		var checkCerts bool
		for _, c := range certs {
			for _, sc := range siteCerts {
				if c.Equal(sc) {
					break
				}
			}
			if !checkCerts {
				result = append(result, SiteCertMatch{
					Domain: d,
					Match:  false,
				})
				continue C1
			}
		}
	}

	return result, nil
}
