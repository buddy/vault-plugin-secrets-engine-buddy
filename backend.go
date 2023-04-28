package buddysecrets

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
	"sync"
	"time"
)

type buddySecretBackend struct {
	*framework.Backend
	client *client
	lock   sync.RWMutex
}

func backend() *buddySecretBackend {
	var b = buddySecretBackend{}
	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(&b),
				pathRotateConfig(&b),
				pathRole(&b),
				pathRoles(&b),
				pathToken(&b),
			},
		),
		Secrets: []*framework.Secret{
			secretToken(&b),
		},
		Invalidate: b.invalidate,
	}
	return &b
}

func (b *buddySecretBackend) getNewClient(config *buddyConfig) (*client, error) {
	apiClient, err := NewApiClient(config)
	if err != nil {
		return nil, err
	}
	c := &client{
		expiration: time.Now().Add(clientLifetime),
		apiClient:  apiClient,
	}
	return c, nil
}

func (b *buddySecretBackend) getClient(ctx context.Context, s logical.Storage) (*client, error) {
	b.lock.RLock()
	if b.client.Valid() {
		b.lock.RUnlock()
		return b.client, nil
	}
	b.lock.RUnlock()
	b.lock.Lock()
	defer b.lock.Unlock()
	// we must check again because in the meantime something could have changed client
	if b.client.Valid() {
		return b.client, nil
	}
	config, err := b.getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	apiClient, err := NewApiClient(config)
	if err != nil {
		return nil, err
	}
	c := &client{
		expiration: time.Now().Add(clientLifetime),
		apiClient:  apiClient,
	}
	b.client = c
	return c, nil
}

// reset clears the backend's client
func (b *buddySecretBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

func (b *buddySecretBackend) invalidate(_ context.Context, key string) {
	switch key {
	case "config":
		b.reset()
	}
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

const backendHelp = `
The Buddy secrets engine dynamically generates short time lived
personal access tokens based on predefined scopes and filters.

After mounting this secrets engine, credentials to manage Buddy tokens
must be configured with the "config/" endpoints. You can generate tokens
using the "tokens/" endpoints.  
`
