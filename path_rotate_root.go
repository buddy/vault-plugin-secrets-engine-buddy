package buddysecrets

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"time"
)

func pathRotateConfig(b *buddySecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: "rotate-root",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.pathRotateRoot,
				ForwardPerformanceSecondary: true,
				ForwardPerformanceStandby:   true,
			},
		},
		HelpSynopsis:    rotateHelpSyn,
		HelpDescription: rotateHelpDesc,
	}
}

func (b *buddySecretBackend) rotateRootToken(ctx context.Context, sys *logical.Request) error {
	config, err := b.getConfig(ctx, sys.Storage)
	if err != nil {
		return err
	}
	if config == nil || config.Token == "" {
		return fmt.Errorf("root token not provided through config")
	}
	client, err := b.getNewClient(config)
	if err != nil {
		return err
	}
	token, err := client.CreateToken("vault root token", config.TokenTtlInDays, config.TokenIpRestrictions, config.TokenWorkspaceRestrictions, config.TokenScopes)
	if err != nil {
		return err
	}
	expiresAt, err := time.Parse(time.RFC3339, token.ExpiresAt)
	if err != nil {
		return err
	}
	oldTokenId := config.TokenId
	config.Token = token.Token
	config.TokenId = token.Id
	config.TokenExpiresAt = expiresAt
	config.TokenNoExpiration = false
	config.TokenScopes = token.Scopes
	config.TokenIpRestrictions = token.IpRestrictions
	config.TokenWorkspaceRestrictions = token.WorkspaceRestrictions
	if config.TokenAutoRotate {
		config.TokenAutoRotateAt = time.Date(expiresAt.Year(), expiresAt.Month(), expiresAt.Day()-1, expiresAt.Hour(), expiresAt.Minute(), expiresAt.Second(), expiresAt.Nanosecond(), expiresAt.Location())
	}
	err = b.saveConfig(ctx, config, sys.Storage)
	if err != nil {
		_ = client.DeleteToken(token.Id)
		return err
	}
	_ = client.DeleteToken(oldTokenId)
	return nil
}

func (b *buddySecretBackend) pathRotateRoot(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	err := b.rotateRootToken(ctx, req)
	return nil, err
}

const rotateHelpSyn = "Attempt to rotate the root credentials used to communicate with Buddy"

const rotateHelpDesc = `
This path will attempt to generate new root token for the user.
The new token will have the sames scopers and filters as the old one
The old token will be removed if possible.
The new token won't be returned from this endpoint, nor the read config
`
