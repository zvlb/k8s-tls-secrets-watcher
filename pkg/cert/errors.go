package cert

import "errors"

var (
	ErrCertNotFound          = errors.New("certificate not found")
	ErrKeyNotFound           = errors.New("key not found")
	ErrKeyNotSupportedFormat = errors.New("key not ECDSA or RSA format")
	ErrFailedDecodeCert      = errors.New("failed to decode certificate")
	ErrFailedDecodeKey       = errors.New("failed to decode private key")
	ErrWrongKeyForCert       = errors.New("certificate signed by wrong public key")
	ErrCertExpiredSoon       = errors.New("certificate expired or going to expire soon")
	ErrCertExpired           = errors.New("certificate expired")
)
