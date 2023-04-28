#!/usr/bin/env bash

set -e

VAULT_IMAGE=vault:1.13.2
PLUGIN_NAME="vault-plugin-secrets-buddy"
MNT_PATH="buddy"
DIR="$(cd "$(dirname "$(readlink "$0")")" && pwd)"
PLUGINS="$DIR/tmp/plugins"
mkdir -p "$PLUGINS"

function vault_server_up {
  echo "[Starting]"
  docker run \
    --name=vault \
    --cap-add=IPC_LOCK \
    -e 'VAULT_LOCAL_CONFIG={"plugin_directory": "/plugins"}' \
    -e 'VAULT_ADDR=http://127.0.0.1:8200' \
    -e 'VAULT_DEV_ROOT_TOKEN_ID=root' \
    -p 8200:8200 \
    -v "$PLUGINS:/plugins" \
    --detach \
    $VAULT_IMAGE \
    server -dev >/dev/null
  sleep 2
}

function build_cmd {
  echo "[Building]"
  GOOS=linux go build -o "$PLUGINS/$PLUGIN_NAME" "./cmd/$PLUGIN_NAME"
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
  vault_cmd write buddy/config token=$BUDDY_TOKEN base_url=$BUDDY_BASE_URL insecure=$BUDDY_INSECURE

}

function buddy_rotate_root {
  echo "[Rotating root]"
  vault_cmd write -f buddy/rotate-root
}

function buddy_role_r1 {
  echo "[Role r1]"
  vault_cmd write buddy/roles/r1 \
    ttl=30 \
    scopes=WORKSPACE
}

function buddy_role_r2() {
  echo "[Role r2]"
  vault_cmd write buddy/roles/r2 \
    ttl=180 \
    max_ttl=3600 \
    scopes=WORKSPACE,TOKEN_INFO \
    ip_restrictions=127.0.0.1 \
    workspace_restrictions=a,b
}

function buddy_test_role_r1 {
  echo "[Test role r1]"
  ROLE_R1=$(vault_cmd read -format=json buddy/roles/r1)
  ROLE_R1_TTL=$(echo $ROLE_R1 | jq -r .data.ttl)
  ROLE_R1_SCOPES=$(echo $ROLE_R1 | jq -r '.data.scopes | join(",")')
  test_equal "$ROLE_R1_TTL" "30" "TTL $ROLE_R1_TTL not equal 30"
  test_equal "$ROLE_R1_SCOPES" 'WORKSPACE' 'Scopes $ROLE_R1_SCOPES not equal WORKSPACE'
}

function buddy_test_role_r2() {
  echo "[Test role r2]"
  ROLE_R2=$(vault_cmd read -format=json buddy/roles/r2)
  ROLE_R2_TTL=$(echo $ROLE_R2 | jq -r .data.ttl)
  ROLE_R2_MAX_TTL=$(echo $ROLE_R2 | jq -r .data.max_ttl)
  ROLE_R2_SCOPES=$(echo $ROLE_R2 | jq -r '.data.scopes | join(",")')
  ROLE_R2_IP=$(echo $ROLE_R2 | jq -r '.data.ip_restrictions | join(",")')
  ROLE_R2_WORKSPACE=$(echo $ROLE_R2 | jq -r '.data.workspace_restrictions | join(",")')
  test_equal "$ROLE_R2_TTL" "180" "TTL $ROLE_R2_TTL not equal 180"
  test_equal "$ROLE_R2_MAX_TTL" "3600" "Max TTL $ROLE_R2_MAX_TTL not equal 3600"
  test_equal "$ROLE_R2_SCOPES" 'WORKSPACE,TOKEN_INFO' 'Scopes $ROLE_R2_SCOPES not equal WORKSPACE,TOKEN_INFO'
  test_equal "$ROLE_R2_IP" '127.0.0.1' 'IP restrictions $ROLE_R2_IP not equal 127.0.0.1'
  test_equal "$ROLE_R2_WORKSPACE" 'a,b' 'Workspace restrictions $ROLE_R2_WORKSPACE not equal a,b'
}

function test_equal {
  if [ "$1" != "$2" ]; then
    echo "$3"
    exit 1
  fi
}

function test_not_empty {
  if [ -z "$1" ]; then
    echo "$2"
    exit 1
  fi
}

function buddy_test_creds_r1 {
  echo "[Test creds r1]"
  CREDS_R1=$(vault_cmd read -format=json buddy/creds/r1)
  CREDS_R1_LEASE=$(echo $CREDS_R1 | jq -r .lease_duration)
  CREDS_R1_TOKEN=$(echo $CREDS_R1 | jq -r .token)
  test_equal "$CREDS_R1_LEASE" "30" "Lease $CREDS_R1_LEASE not equal 30"
  test_not_empty "$CREDS_R1_TOKEN" "Token should not be empty"
}

function buddy_test_creds_r2 {
  echo "[Test creds r2]"
  CREDS_R2=$(vault_cmd read -format=json buddy/creds/r2)
  CREDS_R2_LEASE=$(echo $CREDS_R2 | jq -r .lease_duration)
  CREDS_R2_TOKEN=$(echo $CREDS_R2 | jq -r .token)
  CREDS_R2_ID=$(echo $CREDS_R2 | jq -r .lease_id)
  test_equal "$CREDS_R2_LEASE" "180" "Lease $CREDS_R2_LEASE not equal 180"
  test_not_empty "$CREDS_R2_TOKEN" "Token should not be empty"
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
}

trap cleanup EXIT

build_cmd
vault_server_up
vault_login
vault_register_plugin
vault_enable_plugin
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

# TODO pobierac info o tokenie bezposrednio z api i sprawdzac czy faktycznie jest tak jak byc powinno
