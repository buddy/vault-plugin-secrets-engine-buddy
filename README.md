# The [HCP Vault](https://www.vaultproject.io) plugin for [Buddy](https://buddy.works).

## Build

Pre-built binaries for Linux, macOS and Windows can be found in the [releases directory](https://github.com/buddy/vault-plugin-secrets-buddy/releases). For other platforms, there are currently no pre-built binaries available.

To compile a new binary, clone this repository and run `make` from the project directory.

## Installation

The HCP Vault plugin system is documented on the Hashicorp's [Vault documentation site](https://www.vaultproject.io/docs/internals/plugins.html).

To install the vault, define a plugin directory using the `plugin_directory` configuration directive and place the generate `vault-plugin-secrets-buddy` executable in that directory.

Example commands for registering and starting the plugin:
```sh
$ vault plugin register \
    -sha256=$(openssl sha256 < vault-plugin-secrets-buddy) \
    -command="vault-plugin-secrets-buddy" \
    secret buddy
Success! Registered plugin: buddy

$ vault secrets enable buddy
Success! Enabled the buddy secrets engine at: buddy/
```

## Usage

### Configuration

The short-lived tokens are created using the [personal access token](/docs/api/getting-started/oauth2/personal-access-token) (or root token) in Buddy. The root token must have the scope `TOKEN_MANAGE`.

```sh
$ vault write buddy/config token=ROOT_TOKEN
Success! Data written to: buddy/config
```

Available options:

`token_auto_rotate` - enables auto-rotation of root token the day before the expiration. When error is encountered plugin will try every hour to rotate it until the token expires.

`token_ttl_in_days` - The TTL of the new rotated root token in days. Default: 30. Min: 2

`base_url` - The Buddy API base url. You may need to set this to your Buddy On-Premises API endpoint. Default: `https://api.buddy.works`

`insecure` - Disable SSL verification of API calls. You may need to set this to `true` if you are using Buddy On-Premises without signed certificate. Default: false

### Rotating root token

Attempt to rotate the root credentials used to communicate with Buddy. Old token will be removed

```sh
$ vault write -f buddy/rotate-root
Success! Data written to: buddy/rotate-root
```

## Roles

Create a role and read its current credentials:

```sh
$ vault write buddy/roles/r1 \
    ttl=30 \
    scopes=WORKSPACE,EXECUTION_RUN
Success! Data written to: buddy/roles/r1    
```

All options:

`ttl` - Default lease for generated token. Vault will automatically revoke token after the duration. If not set or set to 0, will use system default.

`max_ttl` - Maximum duration that generated token cab be extended to. If not set or set to 0, will use system default.

`scopes` - The comma separated list of scopes

`ip_restrictions` - The comma separated list of IP addresses

`workspace_restrictions` - The comma separated list of workspace domains

Read the credentials:

```sh
$ vault read buddy/creds/r1
Key                Value
---                -----
lease_id           buddy/creds/r1/EUwKywNTUy7Msa6jWs3FR8Fq
lease_duration     30s
lease_renewable    true
token              5d225d46-c361-4b3f-ba84-9d83891313a0
```

Grab token into env variable:

```sh
TOKEN=$(vault read -format=json buddy/creds/r1 | jq -r .data.token)
```




