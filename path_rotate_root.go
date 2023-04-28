package buddysecrets

import (
	"context"
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

func (b *buddySecretBackend) pathRotateRoot(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil || config.Token == "" {
		return logical.ErrorResponse("root token not provided through config"), nil
	}
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	token, err := client.CreateToken("vault root token", config.TokenTtlInDays, config.TokenIpRestrictions, config.TokenWorkspaceRestrictions, config.TokenScopes)
	if err != nil {
		return nil, err
	}
	expiresAt, _ := time.Parse(time.RFC3339, token.ExpiresAt)
	oldTokenId := config.TokenId
	config.Token = token.Token
	config.TokenId = token.Id
	config.TokenExpiresAt = expiresAt
	config.TokenScopes = token.Scopes
	config.TokenIpRestrictions = token.IpRestrictions
	config.TokenWorkspaceRestrictions = token.WorkspaceRestrictions
	err = b.saveConfig(ctx, config, req.Storage)
	if err != nil {
		_ = client.DeleteToken(token.Id)
		return nil, err
	}
	_ = client.DeleteToken(oldTokenId)
	return nil, nil
}

const rotateHelpSyn = "Attempt to rotate the root credentials used to communicate with Buddy"

const rotateHelpDesc = `
This path will attempt to generate new root token for the user.
The new token will have the sames scopers and filters as the old one
The old token will be removed if possible.
The new token won't be returned from this endpoint, nor the read config
`
