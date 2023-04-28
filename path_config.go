package buddysecrets

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"time"
)

const (
	configStoragePath = "config"
	// default token ttl is 30 days
	defaultRootTokenTTL = 30
	// default api endpoint
	defaultBaseUrl = "https://api.buddy.works"
)

type buddyConfig struct {
	Token                      string    `json:"token"`
	BaseUrl                    string    `json:"base_url"`
	Insecure                   bool      `json:"insecure"`
	TokenTtlInDays             int       `json:"token_ttl_in_days"`
	TokenId                    string    `json:"token_id"`
	TokenExpiresAt             time.Time `json:"token_expires_at"`
	TokenScopes                []string  `json:"token_scopes"`
	TokenIpRestrictions        []string  `json:"token_ip_restrictions"`
	TokenWorkspaceRestrictions []string  `json:"token_workspace_restrictions"`
}

func pathConfig(b *buddySecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "The Personal Access Token. Must have scope `TOKEN_MANAGE`. Required",
			},
			"token_ttl_in_days": {
				Type:        framework.TypeInt,
				Description: "The TTL of the new rotated root token in days. Default: 30",
			},
			"base_url": {
				Type:        framework.TypeString,
				Description: "The Buddy API base url. You may need to set this to your Buddy On-Premises API endpoint. Default: `https://api.buddy.works`",
			},
			"insecure": {
				Type:        framework.TypeBool,
				Description: "Disable SSL verification of API calls. You may need to set this to `true` if you are using Buddy On-Premises without signed certificate. Default: false",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    confHelpSyn,
		HelpDescription: confHelpDesc,
	}
}

func (b *buddySecretBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		if req.Operation == logical.UpdateOperation {
			return logical.ErrorResponse("config not found during update operation"), nil
		}
		config = new(buddyConfig)
	}
	if token, ok := data.GetOk("token"); ok {
		config.Token = token.(string)
	}
	if baseUrl, ok := data.GetOk("base_url"); ok {
		config.BaseUrl = baseUrl.(string)
	}
	if insecure, ok := data.GetOk("insecure"); ok {
		config.Insecure = insecure.(bool)
	}
	if tokenTTL, ok := data.GetOk("token_ttl_in_days"); ok {
		config.TokenTtlInDays = tokenTTL.(int)
	}
	if config.BaseUrl == "" {
		config.BaseUrl = defaultBaseUrl
	}
	if config.TokenTtlInDays <= 0 {
		config.TokenTtlInDays = defaultRootTokenTTL
	}
	if config.Token == "" {
		return logical.ErrorResponse("token must be provided"), nil
	}
	client, err := b.getNewClient(config)
	if err != nil {
		return nil, err
	}
	token, err := client.GetRootToken()
	if err != nil {
		return nil, err
	}
	expiresAt, _ := time.Parse(time.RFC3339, token.ExpiresAt)
	config.TokenExpiresAt = expiresAt
	config.TokenId = token.Id
	config.TokenScopes = token.Scopes
	config.TokenIpRestrictions = token.IpRestrictions
	config.TokenWorkspaceRestrictions = token.WorkspaceRestrictions
	err = b.saveConfig(ctx, config, req.Storage)
	return nil, err
}

func (b *buddySecretBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = new(buddyConfig)
	}
	resp := &logical.Response{
		Data: map[string]interface{}{
			"base_url":          config.BaseUrl,
			"insecure":          config.Insecure,
			"token_ttl_in_days": config.TokenTtlInDays,
		},
	}
	if config.TokenId != "" {
		resp.Data["token_id"] = config.TokenId
		resp.Data["token_expires_at"] = config.TokenExpiresAt
		resp.Data["token_scopes"] = config.TokenScopes
		resp.Data["token_ip_restrictions"] = config.TokenIpRestrictions
		resp.Data["token_workspace_restrictions"] = config.TokenWorkspaceRestrictions
	}
	return resp, nil
}

func (b *buddySecretBackend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)
	if err == nil {
		b.reset()
	}
	return nil, err
}

func (b *buddySecretBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return config != nil, err
}

func (b *buddySecretBackend) getConfig(ctx context.Context, s logical.Storage) (*buddyConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	config := new(buddyConfig)
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}
	return config, nil
}

func (b *buddySecretBackend) saveConfig(ctx context.Context, config *buddyConfig, s logical.Storage) error {
	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return err
	}
	err = s.Put(ctx, entry)
	if err != nil {
		return err
	}
	// reset backend because config changed
	b.reset()
	return nil
}

const confHelpSyn = "Configure the Buddy Secret backend"
const confHelpDesc = `
The Buddy secret backend requires credentials for managing Personal
Access Tokens. This endpoint is used to configure those credentials
as well as default values for the backend in general
`
