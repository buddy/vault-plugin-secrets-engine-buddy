package buddysecrets

import (
	"context"
	"fmt"
	"github.com/buddy/api-go-sdk/buddy"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"time"
)

const (
	configStoragePath = "config"
	// default token ttl is 30 days
	defaultRootTokenTTL = 30
	// min token ttl in days
	minRootTokenTTL = 2
	// default api endpoint
	defaultBaseUrl = "https://api.buddy.works"
)

type buddyConfig struct {
	Token                      string    `json:"token"`
	BaseUrl                    string    `json:"base_url"`
	Insecure                   bool      `json:"insecure"`
	TokenAutoRotate            bool      `json:"token_auto_rotate"`
	TokenAutoRotateAt          time.Time `json:"token_auto_rotate_at"`
	TokenTtlInDays             int       `json:"token_ttl_in_days"`
	TokenId                    string    `json:"token_id"`
	TokenExpiresAt             time.Time `json:"token_expires_at"`
	TokenNoExpiration          bool      `json:"token_no_expiration"`
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
				Description: fmt.Sprintf("The TTL of the new rotated root token in days. Default: %d. Min: %d", defaultRootTokenTTL, minRootTokenTTL),
			},
			"token_auto_rotate": {
				Type:        framework.TypeBool,
				Description: "Enable auto rotating of root token. The day before expiration there will be an attempt to rotate it. When error is encountered plugin will try every hour to rotate it until the token expires.",
			},
			"base_url": {
				Type:        framework.TypeString,
				Description: fmt.Sprintf("The Buddy API base url. You may need to set this to your Buddy On-Premises API endpoint. Default: `%s`", defaultBaseUrl),
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

func hasManageScope(scopes []string) bool {
	for _, scope := range scopes {
		if scope == buddy.TokenScopeTokenManage {
			return true
		}
	}
	return false
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
	if autoRotate, ok := data.GetOk("token_auto_rotate"); ok {
		config.TokenAutoRotate = autoRotate.(bool)
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
	if config.TokenTtlInDays < minRootTokenTTL {
		return logical.ErrorResponse("token ttl must be at least %d days", minRootTokenTTL), nil
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
		return logical.ErrorResponse("invalid token"), nil
	}
	expiresAt, expiresAtErr := time.Parse(time.RFC3339, token.ExpiresAt)
	if config.TokenAutoRotate {
		now := time.Now()
		minExpirationDate := time.Date(now.Year(), now.Month(), now.Day()+minRootTokenTTL, now.Hour(), now.Minute(), now.Second(), now.Nanosecond(), now.Location())
		rotateAt := time.Date(now.Year(), now.Month(), now.Day()+config.TokenTtlInDays-1, now.Hour(), now.Minute(), now.Second(), now.Nanosecond(), now.Location())
		if expiresAtErr == nil && expiresAt.Unix() < rotateAt.Unix() {
			rotateAt = time.Date(expiresAt.Year(), expiresAt.Month(), expiresAt.Day()-1, expiresAt.Hour(), expiresAt.Minute(), expiresAt.Second(), expiresAt.Nanosecond(), expiresAt.Location())
			if rotateAt.Unix() < minExpirationDate.Unix() {
				return logical.ErrorResponse("token expiration date must be after %s, insted it expires at: %s", minExpirationDate.Format(time.RFC3339), expiresAt.Format(time.RFC3339)), nil
			}
		}
		config.TokenAutoRotateAt = rotateAt
	}
	config.TokenExpiresAt = expiresAt
	config.TokenNoExpiration = expiresAtErr != nil
	config.TokenId = token.Id
	config.TokenScopes = token.Scopes
	config.TokenIpRestrictions = token.IpRestrictions
	config.TokenWorkspaceRestrictions = token.WorkspaceRestrictions
	if !hasManageScope(config.TokenScopes) {
		return logical.ErrorResponse("token must have `%s` scope", buddy.TokenScopeTokenManage), nil
	}
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
			"token_auto_rotate": config.TokenAutoRotate,
		},
	}
	if config.TokenAutoRotate {
		resp.Data["token_auto_rotate_at"] = config.TokenAutoRotateAt
	}
	if config.TokenId != "" {
		resp.Data["token_id"] = config.TokenId
		if config.TokenNoExpiration {
			resp.Data["token_expires_at"] = "no expiration date"
		} else {
			resp.Data["token_expires_at"] = config.TokenExpiresAt
		}
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
