# The [HashiCorp Vault](https://www.vaultproject.io) plugin for [Buddy](https://buddy.works).

## Binaries

Pre-built binaries for Linux, macOS and Windows can be found in the [releases directory](https://github.com/buddy/vault-plugin-secrets-engine-buddy/releases). For other platforms, there are currently no pre-built binaries available.

To compile a new binary, clone this repository and run `make` from the project directory.

## Vault installation

The HashiCorp Vault plugin system is documented on the HashiCorp's [Vault documentation site](https://www.vaultproject.io/docs/internals/plugins.html).

To install the vault, define the plugin directory using the `plugin_directory` configuration directive and place the `vault-plugin-secrets-engine-buddy` executable in that directory.

Example commands for registering and starting the plugin:

```sh
$ vault plugin register \
    -sha256=$(openssl sha256 < vault-plugin-secrets-engine-buddy) \
    -command="vault-plugin-secrets-engine-buddy" \
    secret buddy
Success! Registered plugin: buddy

$ vault secrets enable buddy
Success! Enabled the buddy secrets engine at: buddy/
```

## Root token configuration

### Generating token

To create short-lived tokens, you first need to configure a [root token in Buddy](https://buddy.works/docs/api/getting-started/oauth2/personal-access-token). The root token must have the scope `TOKEN_MANAGE`:

<img src="/root-token-config.png" width="450">

>**Note**
>You can fortify your tokens by allowing access from selected IP's and/or workspace domains.

>**Warning**
>It is not possible to set `ip_restrictions` and `workspace_restrictions` in the vault token if they are already defined in the root token – the restrictions are automatically inherited from root to child tokens.

### Saving to vault

Once generated, copy the value of the token and save it to the vault:

```sh
$ vault write buddy/config token=ROOT_TOKEN
Success! Data written to: buddy/config
```

Available options:

- `token_auto_rotate` – enables auto-rotation of the root token one day before the expiration date. If an error is encountered, the plugin will reattempt to rotate the token on every hour until it eventually expires.

    > **Warning**
    > If no auto-rotation is set, the token should be generated with no expiration date.

- `token_ttl_in_days` – the lease time of the rotated root token in days. Default: `30`. Min: `2`
- `base_url` – the Buddy API base URL. You may need to set this in your Buddy On-Premises API endpoint. Default: `https://api.buddy.works`
- `insecure` – disables the SSL verification of the API calls. You may need to set this to `true` if you are using Buddy On-Premises without a signed certificate. Default: `false`

### Rotating root token

Updates the root credentials used for communication with Buddy. Rotating the root token removes the old one. To rotate the token, run

```sh
$ vault write -f buddy/rotate-root
Success! Data written to: buddy/rotate-root
```

## Vault token configuration

### Creating token role

To create a role for the token, run `vault write buddy/roles/ROLE_NAME` with the lease time and scopes.

Example command for creating the RUN_PIPELINE role:

```sh
$ vault write buddy/roles/run_pipeline \
    ttl=30 \
    scopes=WORKSPACE,EXECUTION_RUN
Success! Data written to: buddy/roles/run_pipeline   
```

Available options:

- `ttl` – the default lease time for the generated token after which the token is automatically revoked. If not set or set to `0`, system default is used.
- `max_ttl` – the maximum time the generated token can be extended to before it eventually expires. If not set or set to `0`, system default is used.
- `scopes` – the [list of scopes](https://buddy.works/docs/api/getting-started/oauth2/introduction#supported-scopes) in the role, comma-separated.
- `ip_restrictions` – the list of IP addresses to which the token is restricted, comma-separated. Leave blank if already defined in the root token (the restrictions are automatically inherited).
- `workspace_restrictions` – the list of workspace domains to which the token is restricted, comma-separated. Leave blank if already defined in the root token (the restrictions are automatically inherited).

### Generating role credentials

To generate new credentials, run `vault read buddy/creds/ROLE_NAME`:

```sh
$ vault read buddy/creds/run_pipeline
Key                Value
---                -----
lease_id           buddy/creds/run_pipeline/EUwKywNTUy7Msa6jWs3FR8Fq
lease_duration     30s
lease_renewable    true
token              5d225d46-c361-4b3f-ba84-9d83891313a0
```

### Extend/Revoke

To extend the lease time of the token, run
```sh
$ vault lease renew $lease_id
```

To revoke the token, run
```sh
$ vault lease revoke $lease_id
```

### Saving into variable

To save the token into an environment variable, run

```sh
$ TOKEN=$(vault read -format=json buddy/creds/run_pipeline | jq -r .data.token)
```
