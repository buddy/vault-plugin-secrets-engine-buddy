#!/usr/bin/env bash

set -e

MNT_PATH="buddy"
PLUGIN_NAME="vault-plugin-secrets-engine-buddy"

DIR="$(cd "$(dirname "$(readlink "$0")")" && pwd)"

echo "Creating tmp dir"
SCRATCH="$DIR/tmp"
mkdir -p "$SCRATCH/plugins"

echo "Configuring Vault"
tee "$SCRATCH/vault.hcl" > /dev/null <<EOF
plugin_directory = "$SCRATCH/plugins"
EOF

export VAULT_DEV_ROOT_TOKEN_ID="root"
export VAULT_ADDR="http://127.0.0.1:8200"

echo "Starting Vault"
TF_LOG=DEBUG vault server -dev -log-level="debug" -config="$SCRATCH/vault.hcl" &
VAULT_PID=$!
sleep 2

function cleanup {
  echo " Exiting..."
  kill -9 "$VAULT_PID"
  rm -rf "$SCRATCH"
  exit 0
}
trap cleanup EXIT

echo "Logging into Vault"
vault login root &>/dev/null

echo "Building"
go build -o "$SCRATCH/plugins/$PLUGIN_NAME" "./cmd/$PLUGIN_NAME" 
SHASUM=$(shasum -a 256 "$SCRATCH/plugins/$PLUGIN_NAME" | cut -d " " -f1)

echo "Registering"
vault write sys/plugins/catalog/$PLUGIN_NAME sha_256="$SHASUM" command="$PLUGIN_NAME"

echo "Mounting"
vault secrets enable -path=$MNT_PATH -plugin-name=$PLUGIN_NAME plugin

echo "Ready!"
wait "$VAULT_PID"

