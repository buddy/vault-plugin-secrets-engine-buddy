package buddysecrets

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	SecretTypeToken        = "token"
	TokenDefaultExpiration = 3650
)

func secretToken(b *buddySecretBackend) *framework.Secret {
	return &framework.Secret{
		Type:   SecretTypeToken,
		Renew:  b.tokenRenew,
		Revoke: b.tokenRevoke,
	}
}

func (b *buddySecretBackend) tokenRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("internal data 'role' not found")
	}
	role, err := getRole(ctx, roleRaw.(string), req.Storage)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = role.Ttl
	resp.Secret.MaxTTL = role.MaxTTL
	return resp, nil
}

func (b *buddySecretBackend) tokenRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	tokenIdRaw, ok := req.Secret.InternalData["token_id"]
	if !ok {
		return nil, fmt.Errorf("internal data 'token_id' not found")
	}
	tokenId := tokenIdRaw.(string)
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	err = client.DeleteToken(tokenId)
	return nil, err
}

func (b *buddySecretBackend) pathTokenRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
	roleName := d.Get("role").(string)
	role, err := getRole(ctx, roleName, req.Storage)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role '%s' does not exist", roleName)), nil
	}
	token, err := client.CreateToken(fmt.Sprintf("vault token for '%s' role", roleName), TokenDefaultExpiration, role.IpRestrictions, role.WorkspaceRestrictions, role.Scopes)
	if err != nil {
		return nil, err
	}
	data := map[string]interface{}{
		"token": token.Token,
	}
	internalData := map[string]interface{}{
		"role":     roleName,
		"token_id": token.Id,
	}
	resp := b.Secret(SecretTypeToken).Response(data, internalData)
	resp.Secret.TTL = role.Ttl
	resp.Secret.MaxTTL = role.MaxTTL
	return resp, nil
}

func pathToken(b *buddySecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("creds/%s", framework.GenericNameRegex("role")),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeLowerCaseString,
				Description: "The name of the Vault role",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback:                    b.pathTokenRead,
				ForwardPerformanceSecondary: true,
				ForwardPerformanceStandby:   true,
			},
		},
		HelpSynopsis:    tokenHelpSyn,
		HelpDescription: tokenHelpDesc,
	}
}

const tokenHelpSyn = "Request Personal Access Token for the given Vault role."
const tokenHelpDesc = `
This path creates or updates the dynamic Personal Access Token.
It will be automatically deleted when the lease time has expired.
`
