package buddysecrets

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"sort"
	"time"
)

const (
	rolesStoragePath = "roles"
)

type roleEntry struct {
	Ttl                   time.Duration `json:"ttl"`
	MaxTTL                time.Duration `json:"max_ttl"`
	Scopes                []string      `json:"scopes"`
	IpRestrictions        []string      `json:"ip_restrictions"`
	WorkspaceRestrictions []string      `json:"workspace_restrictions"`
}

func pathRole(b *buddySecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "The name of the role",
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "The default lease time for the generated vault token after which the token is automatically revoked. If not set or set to 0, system default is used.",
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "The maximum time the generated token can be extended to before it eventually expires. If not set or set to 0, system default is used.",
			},
			"scopes": {
				Type:        framework.TypeCommaStringSlice,
				Description: "The list of scopes in the role, comma-separated.",
			},
			"ip_restrictions": {
				Type:        framework.TypeCommaStringSlice,
				Description: "The list of IP addresses to which the token is restricted, comma-separated.",
			},
			"workspace_restrictions": {
				Type:        framework.TypeCommaStringSlice,
				Description: "The list of workspace domains to which the token is restrictred, comma-separated.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathRoleRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathRoleWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRoleWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathRoleDelete,
			},
		},
		ExistenceCheck:  b.pathRoleExistenceCheck,
		HelpSynopsis:    roleHelpSyn,
		HelpDescription: roleHelpDesc,
	}
}

func saveRole(ctx context.Context, s logical.Storage, c *roleEntry, name string) error {
	sort.Strings(c.Scopes)
	sort.Strings(c.IpRestrictions)
	sort.Strings(c.WorkspaceRestrictions)
	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", rolesStoragePath, name), c)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func getRole(ctx context.Context, name string, s logical.Storage) (*roleEntry, error) {
	entry, err := s.Get(ctx, fmt.Sprintf("%s/%s", rolesStoragePath, name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	role := new(roleEntry)
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}

func (b *buddySecretBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)
	role, err := getRole(ctx, name, req.Storage)
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *buddySecretBackend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	err := req.Storage.Delete(ctx, fmt.Sprintf("%s/%s", rolesStoragePath, name))
	return nil, err
}

func (b *buddySecretBackend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role, err := getRole(ctx, name, req.Storage)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	resp := &logical.Response{
		Data: map[string]interface{}{
			"ttl":                    role.Ttl.Seconds(),
			"max_ttl":                role.MaxTTL.Seconds(),
			"scopes":                 role.Scopes,
			"ip_restrictions":        role.IpRestrictions,
			"workspace_restrictions": role.WorkspaceRestrictions,
		},
	}
	return resp, nil
}

func (b *buddySecretBackend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role, err := getRole(ctx, name, req.Storage)
	if err != nil {
		return nil, err
	}
	if role == nil {
		if req.Operation == logical.UpdateOperation {
			return logical.ErrorResponse("role not found during update operation"), nil
		}
		role = &roleEntry{}
	}
	if ttl, ok := d.GetOk("ttl"); ok {
		role.Ttl = time.Duration(ttl.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		role.Ttl = time.Duration(d.Get("ttl").(int)) * time.Second
	}
	if maxTtl, ok := d.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(maxTtl.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		role.MaxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second
	}
	if role.MaxTTL != 0 && role.Ttl > role.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}
	if scopes, ok := d.GetOk("scopes"); ok {
		role.Scopes = scopes.([]string)
	}
	if ipRestrictions, ok := d.GetOk("ip_restrictions"); ok {
		role.IpRestrictions = ipRestrictions.([]string)
	}
	if workspaceRestrictions, ok := d.GetOk("workspace_restrictions"); ok {
		role.WorkspaceRestrictions = workspaceRestrictions.([]string)
	}
	if role.Scopes == nil {
		role.Scopes = []string{}
	}
	if role.IpRestrictions == nil {
		role.IpRestrictions = []string{}
	}
	if role.WorkspaceRestrictions == nil {
		role.WorkspaceRestrictions = []string{}
	}
	err = saveRole(ctx, req.Storage, role, name)
	return nil, err
}

const roleHelpSyn = "Manage the Vault roles used to generate Buddy tokens."

const roleHelpDesc = `
This path allows you to read and write roles that are used to generate
Buddy tokens. If the backend is mounted at "buddy", you would create a
Vault role at "buddy/roles/my_role" and requested credentials from
"buddy/creds/my_role".

When a user requests credentials againts the Vault role, a new personal
access token will be created with parameters configured in the role 
(ttl, scopes, ip & workspace restrictions).
`
