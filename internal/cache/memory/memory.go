package memory

import (
	"fmt"
	"sync"

	"github.com/zvlb/k8s-tls-secrets-watcher/internal/cache"
)

type memoryCache struct {
	certs map[string]cache.CertData

	mu sync.RWMutex
}

func New() cache.Cache {
	return &memoryCache{
		certs: make(map[string]cache.CertData, 0),
	}
}

func (mc *memoryCache) AddOrUpgrade(name, namespace string, certBytes, keyBytes []byte) {
	certData := cache.GetCertData(name, namespace, certBytes, keyBytes)

	mc.mu.Lock()
	mc.certs[fmt.Sprintf("%s/%s", namespace, name)] = certData
	mc.mu.Unlock()
}

func (mc *memoryCache) Delete(name, namespace string) {
	mc.mu.Lock()
	delete(mc.certs, fmt.Sprintf("%s/%s", namespace, name))
	mc.mu.Unlock()
}

func (mc *memoryCache) Get(name, namespace string) (cache.CertData, error) {
	mc.mu.RLock()
	certData, ok := mc.certs[fmt.Sprintf("%s/%s", namespace, name)]
	mc.mu.RUnlock()

	if !ok {
		return cache.CertData{}, cache.ErrCertNotFound
	}

	return certData, nil
}

func (mc *memoryCache) GetAll() map[string]cache.CertData {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	return mc.certs
}
