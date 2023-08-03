#!/usr/bin/env bash

set -e

VAULT_IMAGE=vault:1.13.2
PLUGIN_NAME="vault-plugin-secrets-engine-buddy"
MNT_PATH="buddy"
DIR="$(cd "$(dirname "$(readlink "$0")")" && pwd)"
PLUGINS="$DIR/tmp/plugins"
echo "PLUGINS: $PLUGINS"
mkdir -p "$PLUGINS"

function vault_server_up {
  echo "[Starting]"
  docker run \
    --name=vault \
    --cap-add=IPC_LOCK \
    -e 'VAULT_LOCAL_CONFIG={"plugin_directory": "/plugins"}' \
    -e 'VAULT_ADDR=http://127.0.0.1:8200' \
    -e 'VAULT_DEV_ROOT_TOKEN_ID=root' \
    -e 'BUDDY_FORCE_RORATE=true' \
    -p 8200:8200 \
    -v "$PLUGINS:/plugins" \
    --detach \
    $VAULT_IMAGE \
    server -dev >/dev/null
  sleep 2
}

function build_cmd {
  echo "[Building]"
  go build -o "$PLUGINS/$PLUGIN_NAME" "./cmd/$PLUGIN_NAME"
  SHASUM=$(shasum -a 256 "$PLUGINS/$PLUGIN_NAME" | cut -d " " -f1)
}

function vault_cmd {
  docker exec vault vault "$@"
}

function vault_login {
  echo "[Login]"
  vault_cmd login root
}

function vault_register_plugin {
  echo "[Registering]"
  vault_cmd plugin register -sha256=$SHASUM -command=$PLUGIN_NAME secret $MNT_PATH
}

function vault_enable_plugin {
  echo "[Enabling]"
  vault_cmd secrets enable $MNT_PATH
}

function cleanup {
  echo "[Cleaning]"
  docker rm -f vault >/dev/null 2>&1
}

function buddy_configure {
  echo "[Configuring]"
  echo "token=$BUDDY_TOKEN"
  echo "base_url=$BUDDY_BASE_URL"
  echo "insecure=$BUDDY_INSECURE"
  api_create_token "$BUDDY_TOKEN" '{ "name": "root", "expires_in": 30, "scopes": ["TOKEN_INFO", "WORKSPACE", "TOKEN_MANAGE"] }'
  CONFIG_TOKEN=$(echo "$BUDDY_FETCH_TOKEN" | jq -r '.token')
  vault_cmd write buddy/config token=$CONFIG_TOKEN token_auto_rotate=false base_url=$BUDDY_BASE_URL insecure=$BUDDY_INSECURE
}

function buddy_test_config {
  echo "[Testing config]"
  # empty token
  res=$(vault_cmd write buddy/config token="" 2>&1 || true)
  test_contains "$res" "token must be provided" "Configuration must validate token"
  # wrong token ttl
  res=$(vault_cmd write buddy/config token="abc" token_ttl_in_days=1 2>&1 || true)
  test_contains "$res" "token ttl must be at least 2 days" "Configuration must validate token"
  # wrong token
  res=$(vault_cmd write buddy/config token="abc" base_url=$BUDDY_BASE_URL insecure=$BUDDY_INSECURE 2>&1 || true)
  test_contains "$res" "invalid token" "Configuration must test token"
  # wrong token scopes
  api_create_token "$BUDDY_TOKEN" '{ "name": "test1", "expires_in": 60, "scopes": ["TOKEN_INFO"] }'
  t1=$(echo "$BUDDY_FETCH_TOKEN" | jq -r '.token')
  res=$(vault_cmd write buddy/config token="$t1" base_url=$BUDDY_BASE_URL insecure=$BUDDY_INSECURE 2>&1 || true)
  test_contains "$res" "token must have \`TOKEN_MANAGE\` scope" "Configuration must validate token scope"
  # wrong token exp date
  api_create_token "$BUDDY_TOKEN" '{ "name": "test2", "expires_in": 2, "scopes": ["TOKEN_MANAGE"] }'
  t2=$(echo "$BUDDY_FETCH_TOKEN" | jq -r '.token')
  res=$(vault_cmd write buddy/config token="$t2" token_auto_rotate=true base_url=$BUDDY_BASE_URL insecure=$BUDDY_INSECURE 2>&1 || true)
  test_contains "$res" "token expiration date must be set after" "Configuration must validate token expiration date"
  # read valid config
  api_create_token "$BUDDY_TOKEN" '{ "name": "test3", "expires_in": 10, "scopes": ["TOKEN_MANAGE"] }'
  t3=$(echo "$BUDDY_FETCH_TOKEN" | jq -r '.token')
  vault_cmd write buddy/config token="$t3" base_url=$BUDDY_BASE_URL insecure=$BUDDY_INSECURE
  res=$(vault_cmd read buddy/config)
  test_regex "$res" "base_url[[:space:]]+$BUDDY_BASE_URL" "Config must have base_url key"
  test_regex "$res" "insecure[[:space:]]+$BUDDY_INSECURE" "Config must have insecure key"
  test_regex "$res" "token_auto_rotate[[:space:]]+false" "Config must have token_auto_rotate key"
  test_regex "$res" "token_expires_at" "Config must have token_expires_at key"
  test_regex "$res" "token_id" "Config must have token_id key"
  test_regex "$res" "token_ip_restrictions[[:space:]]+<nil>" "Config must have token_ip_restrictions key"
  test_regex "$res" "token_scopes[[:space:]]+\[TOKEN_MANAGE\]" "Config must have token_scopes key"
  test_regex "$res" "token_ttl_in_days[[:space:]]+30" "Config must have token_ttl_in_days key"
  test_regex "$res" "token_workspace_restrictions[[:space:]]+<nil>" "Config must have token_workspace_restrictions key"
}

function api_fetch_token {
  BUDDY_FETCH_TOKEN=$(curl -s -k -H "Authorization: Bearer $1" "$BUDDY_BASE_URL/user/token")
}

function api_create_token {
  BUDDY_FETCH_TOKEN=$(curl -s -k -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $1" -d "$2" "$BUDDY_BASE_URL/user/tokens")
}

function buddy_rotate_root {
  echo "[Rotating root]"
  vault_cmd write -f buddy/rotate-root
  api_fetch_token "$CONFIG_TOKEN"
  test_contains "$BUDDY_FETCH_TOKEN" "Wrong authentication data" "After rotate old token should be removed"
}

function buddy_test_auto_rotate {
  echo "[Test autorotate]"
  api_create_token "$BUDDY_TOKEN" '{ "name": "auto-token", "expires_in": 5, "scopes": ["TOKEN_MANAGE"] }'
  CONFIG_AUTO_TOKEN=$(echo "$BUDDY_FETCH_TOKEN" | jq -r '.token')
  vault_cmd write buddy/config token=$CONFIG_AUTO_TOKEN token_auto_rotate=true base_url=$BUDDY_BASE_URL insecure=$BUDDY_INSECURE
  res=$(vault_cmd read --format=json buddy/config)
  AUTO_ROTATE_AT_BEFORE=$(echo "$res" | jq -r '.data.token_auto_rotate_at')
  AUTO_ROTATE_EXPIRES_BEFORE=$(echo "$res" | jq -r '.data.token_expires_at')
  AUTO_ROTATE_ID_BEFORE=$(echo "$res" | jq -r '.data.token_id')
  sleep 60
  res=$(vault_cmd read --format=json buddy/config)
  AUTO_ROTATE_AT_AFTER=$(echo "$res" | jq -r '.data.token_auto_rotate_at')
  AUTO_ROTATE_EXPIRES_AFTER=$(echo "$res" | jq -r '.data.token_expires_at')
  AUTO_ROTATE_ID_AFTER=$(echo "$res" | jq -r '.data.token_id')
  test_not_equal "$AUTO_ROTATE_AT_BEFORE" "$AUTO_ROTATE_AT_AFTER" "token_auto_rotate_at must change after rotate"
  test_not_equal "$AUTO_ROTATE_EXPIRES_BEFORE" "$AUTO_ROTATE_EXPIRES_AFTER" "token_expires_at must change after rotate"
  test_not_equal "$AUTO_ROTATE_ID_BEFORE" "$AUTO_ROTATE_ID_AFTER" "token_id must change after rotate"
}

function buddy_role_r1 {
  echo "[Role r1]"
  vault_cmd write buddy/roles/r1 \
    ttl=30 \
    scopes=WORKSPACE,TOKEN_INFO
}

function buddy_role_r2() {
  echo "[Role r2]"
  vault_cmd write buddy/roles/r2 \
    ttl=180 \
    max_ttl=3600 \
    scopes=WORKSPACE,TOKEN_INFO \
    workspace_restrictions=a,b
}

function buddy_test_role_r1 {
  echo "[Test role r1]"
  ROLE_R1=$(vault_cmd read buddy/roles/r1)
  test_regex "$ROLE_R1" "ip_restrictions[[:space:]]+\[\]" "Role r1 must have ip_restrictions=[]"
  test_regex "$ROLE_R1" "max_ttl[[:space:]]+0s" "Role r1 must have max_ttl=0s"
  test_regex "$ROLE_R1" "scopes[[:space:]]+\[TOKEN_INFO WORKSPACE\]" "Role r1 must have scopes=[TOKEN_INFO WORKSPACE]"
  test_regex "$ROLE_R1" "ttl[[:space:]]+30s" "Role r1 must have ttl=30s"
  test_regex "$ROLE_R1" "workspace_restrictions[[:space:]]+\[\]" "Role r1 must workspace_restrictions=[]"
}

function buddy_test_role_r2() {
  echo "[Test role r2]"
  ROLE_R2=$(vault_cmd read buddy/roles/r2)
  test_regex "$ROLE_R2" "ip_restrictions[[:space:]]+\[\]" "Role r2 must have ip_restrictions=[]"
  test_regex "$ROLE_R2" "max_ttl[[:space:]]+1h" "Role r2 must have max_ttl=1h"
  test_regex "$ROLE_R2" "scopes[[:space:]]+\[TOKEN_INFO WORKSPACE\]" "Role r2 must have scopes=[TOKEN_INFO WORKSPACE]"
  test_regex "$ROLE_R2" "ttl[[:space:]]+3m" "Role r2 must have ttl=3m"
  test_regex "$ROLE_R2" "workspace_restrictions[[:space:]]+\[a b\]" "Role r2 must workspace_restrictions=[a b]"
}

function test_equal {
  if [ "$1" != "$2" ]; then
    echo "$3"
    exit 1
  fi
}

function test_not_equal {
  if [ "$1" == "$2" ]; then
    echo "$3"
    exit 1
  fi
}

function test_contains {
  if [[ "$1" != *"$2"* ]]; then
    echo "$3"
    exit 1
  fi
}

function test_regex {
  if [[ ! "$1" =~ $2 ]]; then
    echo "$3"
    exit 1
  fi
}

function buddy_test_creds_r1 {
  echo "[Test creds r1]"
  CREDS_R1=$(vault_cmd read buddy/creds/r1)
  test_regex "$CREDS_R1" "lease_id[[:space:]]+buddy/creds/r1/" "Creds r1 must have lease_id"
  test_regex "$CREDS_R1" "lease_duration[[:space:]]+30s" "Creds r1 must have lease_duration=30s"
  test_regex "$CREDS_R1" "lease_renewable[[:space:]]+true" "Creds r1 must have lease_renewable=true"
  test_regex "$CREDS_R1" "token[[:space:]]+(.*-.*-.*-.*-.*)" "Creds r1 must have token"
  api_fetch_token "${BASH_REMATCH[1]}"
  CREDS_R1_SCOPES=$(echo $BUDDY_FETCH_TOKEN | jq -r '.scopes | sort | join(",")')
  test_equal "$CREDS_R1_SCOPES" 'TOKEN_INFO,WORKSPACE' "Scopes \$CREDS_R1_SCOPES: $CREDS_R1_SCOPES not equal TOKEN_INFO,WORKSPACE"
}

function buddy_test_creds_r2 {
  echo "[Test creds r2]"
  CREDS_R2=$(vault_cmd read buddy/creds/r2)
  test_regex "$CREDS_R2" "lease_id[[:space:]]+(buddy/creds/r2/[^[:space:]]+)" "Creds r2 must have lease_id"
  CREDS_R2_ID="${BASH_REMATCH[1]}"
  test_regex "$CREDS_R2" "lease_duration[[:space:]]+3m" "Creds r2 must have lease_duration=3m"
  test_regex "$CREDS_R2" "lease_renewable[[:space:]]+true" "Creds r2 must have lease_renewable=true"
  test_regex "$CREDS_R2" "token[[:space:]]+(.*-.*-.*-.*-.*)" "Creds r2 must have token"
  api_fetch_token "${BASH_REMATCH[1]}"
  CREDS_R2_SCOPES=$(echo $BUDDY_FETCH_TOKEN | jq -r '.scopes | sort | join(",")')
  CREDS_R2_WORKSPACE_RESTRICTINOS=$(echo $BUDDY_FETCH_TOKEN | jq -r '.workspace_restrictions | sort | join(",")')
  test_equal "$CREDS_R2_SCOPES" 'TOKEN_INFO,WORKSPACE' "Scopes \$CREDS_R2_SCOPES: $CREDS_R2_SCOPES not equal TOKEN_INFO,WORKSPACE"
  test_equal "$CREDS_R2_WORKSPACE_RESTRICTINOS" 'a,b' "Workspace restrictions \$CREDS_R2_WORKSPACE_RESTRICTINOS: $CREDS_R2_WORKSPACE_RESTRICTINOS not equal a,b"
}

function buddy_test_creds_r2_renew {
  echo "[Test creds r2 renew]"
  RENEW_R2=$(vault_cmd lease renew -format=json "$CREDS_R2_ID")
  RENEW_R2_LEASE=$(echo $RENEW_R2 | jq -r .lease_duration)
  test_equal "$RENEW_R2_LEASE" "180" "Lease $RENEW_R2_LEASE not equal 180"
}

function buddy_test_creds_r2_revoke {
  echo "[Test creds r2 revoke]"
  vault_cmd lease revoke "$CREDS_R2_ID"
  api_fetch_token $CREDS_R2_TOKEN
  REVOKE_R2_MESSAGE=$(echo $BUDDY_FETCH_TOKEN | jq -r '.errors[0].message')
  test_equal "$REVOKE_R2_MESSAGE" "Wrong authentication data" "Token \$CREDS_R2_TOKEN not revoked"
}

trap cleanup EXIT

build_cmd
vault_server_up
vault_login
vault_register_plugin
vault_enable_plugin
buddy_test_config
buddy_test_auto_rotate
buddy_configure
buddy_role_r1
buddy_test_role_r1
buddy_test_creds_r1
buddy_rotate_root
buddy_role_r2
buddy_test_role_r2
buddy_test_creds_r2
buddy_test_creds_r2_renew
buddy_test_creds_r2_revoke
