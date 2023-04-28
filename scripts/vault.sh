#!/usr/bin/env bash

set -e

export VAULT_ADDR="http://127.0.0.1:8200"

vault "$@"

