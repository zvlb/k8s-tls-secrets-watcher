package memory

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/zvlb/k8s-tls-secrets-watcher/internal/cache"
	"github.com/zvlb/k8s-tls-secrets-watcher/pkg/cert"

	"github.com/stretchr/testify/require"
)

func Test_AddOrUpgrade(t *testing.T) {
	type testCase struct {
		caseName     string
		name         string
		namespace    string
		cert         []byte
		key          []byte
		wantError    error
		wantCertData cache.CertData
	}

	add_Case := func(
		tc testCase,
	) func(*testing.T) {
		return func(t *testing.T) {
			t.Helper()
			t.Parallel()
			req := require.New(t)

			memoryCache := New()
			memoryCache.AddOrUpgrade(tc.name, tc.namespace, tc.cert, tc.key)

			if tc.caseName == "get note exist cert" {
				certData, err := memoryCache.Get("some", "some")
				req.Equal(tc.wantCertData, certData)
				req.Equal(tc.wantError, err)
				return
			}

			certData, err := memoryCache.Get(tc.name, tc.namespace)
			req.Equal(tc.wantError, err)
			req.Equal(tc.wantCertData, certData)
		}
	}

	okCertBytes, okKeyBytes := generateCert(time.Now().Add(6*30*24*time.Hour), []string{"google.com"})
	okCert, err := cert.GetCertificateFromBytes(okCertBytes)
	if err != nil {
		panic(err)
	}
	_, okKeyBytes2 := generateCert(time.Now().Add(6*30*24*time.Hour), []string{"google.com"})

	testCases := []testCase{
		{
			caseName:  "empty cert",
			name:      "test",
			namespace: "test",
			cert:      []byte(""),
			key:       []byte("test"),
			wantError: nil,
			wantCertData: cache.CertData{
				Name:      "test",
				NameSpace: "test",
				Error:     cert.ErrCertNotFound,
			},
		},
		{
			caseName:  "failed decode cert",
			name:      "test",
			namespace: "test",
			cert:      []byte("test"),
			key:       []byte(""),
			wantError: nil,
			wantCertData: cache.CertData{
				Name:      "test",
				NameSpace: "test",
				Error:     cert.ErrFailedDecodeCert,
			},
		},
		{
			caseName:  "empty key",
			name:      "test",
			namespace: "test",
			cert:      okCertBytes,
			key:       []byte(""),
			wantError: nil,
			wantCertData: cache.CertData{
				Name:      "test",
				NameSpace: "test",
				Error:     cert.ErrKeyNotFound,
			},
		},
		{
			caseName:  "failed decode key",
			name:      "test",
			namespace: "test",
			cert:      okCertBytes,
			key:       []byte("test"),
			wantError: nil,
			wantCertData: cache.CertData{
				Name:      "test",
				NameSpace: "test",
				Error:     cert.ErrFailedDecodeKey,
			},
		},
		{
			caseName:  "cert not equal key",
			name:      "test",
			namespace: "test",
			cert:      okCertBytes,
			key:       okKeyBytes2,
			wantError: nil,
			wantCertData: cache.CertData{
				Name:                 "test",
				NameSpace:            "test",
				Certificates:         []*x509.Certificate{okCert},
				CertificateIssuerOrg: []string{"ZVLB"},
				ExpireDate:           okCert.NotAfter.Unix(),
				Domains:              []string{"google.com"},
				CertKeyEqual:         false,
				SiteCertMatch: []cache.SiteCertMatch{
					{
						Domain: "google.com",
						Match:  false,
					},
				},
				Error: nil,
			},
		},
		{
			caseName:     "get note exist cert",
			name:         "test",
			namespace:    "test",
			cert:         okCertBytes,
			key:          okKeyBytes,
			wantError:    cache.ErrCertNotFound,
			wantCertData: cache.CertData{},
		},
		{
			caseName:  "ok test",
			name:      "test",
			namespace: "test",
			cert:      okCertBytes,
			key:       okKeyBytes,
			wantError: nil,
			wantCertData: cache.CertData{
				Name:                 "test",
				NameSpace:            "test",
				Certificates:         []*x509.Certificate{okCert},
				CertificateIssuerOrg: []string{"ZVLB"},
				ExpireDate:           okCert.NotAfter.Unix(),
				Domains:              []string{"google.com"},
				CertKeyEqual:         true,
				SiteCertMatch: []cache.SiteCertMatch{
					{
						Domain: "google.com",
						Match:  false,
					},
				},
				Error: nil,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, add_Case(tc))
	}

}

// time.Now().Add(6*30*24*time.Hour)

func generateCert(expirationTime time.Time, domains []string) ([]byte, []byte) {
	ca, err := cert.GenerateCertificateAuthority()
	if err != nil {
		panic(err)
	}

	opts := cert.NewCertOpts(expirationTime, domains...)
	cert, key, err := ca.GenerateCertificate(opts)
	if err != nil {
		panic(err)
	}

	return cert.Bytes(), key.Bytes()
}
