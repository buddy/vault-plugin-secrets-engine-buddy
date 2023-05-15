# The [HCP Vault](https://www.vaultproject.io) plugin for [Buddy](https://buddy.works).

## Binaries

Pre-built binaries for Linux, macOS and Windows can be found in the [releases directory](https://github.com/buddy/vault-plugin-secrets-buddy/releases). For other platforms, there are currently no pre-built binaries available.

To compile a new binary, clone this repository and run `make` from the project directory.

## Vault installation

The HCP Vault plugin system is documented on the Hashicorp's [Vault documentation site](https://www.vaultproject.io/docs/internals/plugins.html).

To install the vault, define the plugin directory using the `plugin_directory` configuration directive and place the `vault-plugin-secrets-buddy` executable in that directory.

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

## Root token configuration

To create short-lived tokens, you first need to configure a [root token in Buddy](/docs/api/getting-started/oauth2/personal-access-token). The root token must have the scope `TOKEN_MANAGE`.

```sh
$ vault write buddy/config token=ROOT_TOKEN
Success! Data written to: buddy/config
```

![Root token config](/root-token-config.png?raw=true)

Available options:

`token_auto_rotate` - enables auto-rotation of the root token one day before the expiration date. If an error is encountered, the plugin will reattempt to rotate the token on every hour until it eventually expires.

> **Warning**
> If no auto-rotation is set, the token should have no expiration date set in Buddy.

`token_ttl_in_days` - the lease time of the rotated root token in days. Default: `30`. Min: `2`

`base_url` - the Buddy API base URL. You may need to set this in your Buddy On-Premises API endpoint. Default: `https://api.buddy.works`

`insecure` - disables the SSL verification of the API calls. You may need to set this to `true` if you are using Buddy On-Premises without a signed certificate. Default: `false`

### Rotating root token

Updates the root credentials used for communication with Buddy. Rotating the root token removes the old one and creates new. To rotate the root token, run `vault write -f buddy/rotate-root`.

```sh
$ vault write -f buddy/rotate-root
Success! Data written to: buddy/rotate-root
```

## Vault token configuration

### Creating role

To create a token with the role, run `vault write buddy/roles/ROLE_NAME` and add the lease time and scopes.

Example command for creating a token with the RUN_PIPELINE role:

```sh
$ vault write buddy/roles/run_pipeline \
    ttl=30 \
    scopes=WORKSPACE,EXECUTION_RUN
Success! Data written to: buddy/roles/run_pipeline   
```

Available options:

`ttl` – the default lease time for the generated vault token after which the token is automatically revoked. If not set or set to `0`, system default is used.

`max_ttl` – the maximum time the generated token can be extended to before it eventually expires. If not set or set to `0`, system default is used.

`scopes` – the list of scopes in the role, comma-separated.

`ip_restrictions` – the list of IP addresses to which the token is restricted, comma-separated.

`workspace_restrictions` – the list of workspace domains to which the token is restrictred, comma-separated.

### Reading role credentials

To check the credentials in the role, run `read buddy/creds/ROLE_NAME`:

```sh
$ vault read buddy/creds/r1
Key                Value
---                -----
lease_id           buddy/creds/r1/EUwKywNTUy7Msa6jWs3FR8Fq
lease_duration     30s
lease_renewable    true
token              5d225d46-c361-4b3f-ba84-9d83891313a0
```

Generating environment variable from token:

```sh
TOKEN=$(vault read -format=json buddy/creds/r1 | jq -r .data.token)
```




