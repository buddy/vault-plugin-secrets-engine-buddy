package buddysecrets

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRoles(b *buddySecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathRolesList,
			},
		},
		HelpSynopsis:    rolesHelpSyn,
		HelpDescription: rolesHelpDesc,
	}
}

func (b *buddySecretBackend) pathRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, rolesStoragePath+"/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

const rolesHelpSyn = "List existing roles."
const rolesHelpDesc = "List existing roles by name."
