package buddysecrets

import (
	"github.com/buddy/api-go-sdk/buddy"
	"time"
)

const (
	clientLifetime = 30 * time.Minute
)

type client struct {
	apiClient  *buddy.Client
	expiration time.Time
}

func (c *client) Valid() bool {
	return c != nil && time.Now().Before(c.expiration)
}

func (c *client) CreateToken(name string, expiresIn int, ipRestrictions []string, workspaceRestrictions []string, scopes []string) (*buddy.Token, error) {
	ops := buddy.TokenOps{
		Name:                  &name,
		IpRestrictions:        &ipRestrictions,
		WorkspaceRestrictions: &workspaceRestrictions,
		Scopes:                &scopes,
		ExpiresIn:             &expiresIn,
	}
	token, _, err := c.apiClient.TokenService.Create(&ops)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (c *client) DeleteToken(tokenId string) error {
	_, err := c.apiClient.TokenService.Delete(tokenId)
	return err
}

func (c *client) GetRootToken() (*buddy.Token, error) {
	token, _, err := c.apiClient.TokenService.GetMe()
	return token, err
}

func NewApiClient(config *buddyConfig) (*buddy.Client, error) {
	return buddy.NewClient(config.Token, config.BaseUrl, config.Insecure)
}
