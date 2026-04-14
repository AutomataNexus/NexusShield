#!/bin/bash
# Launch security-ticker with the NexusShield API token pulled from Vault.
#
# Usage:
#   /opt/NexusShield/launch-ticker.sh                 # foreground
#   /opt/NexusShield/launch-ticker.sh &               # backgrounded in this shell
#
# Called by the Windows launcher (security-ticker.vbs) via WSL.

set -euo pipefail

export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"

# Root token: prefer in-vault canonical location, fall back to .vault-keys.
if [ -z "${VAULT_TOKEN:-}" ]; then
    if [ -r /opt/Prometheus/vault/.vault-keys ]; then
        VAULT_TOKEN=$(grep -oE '"root_token"[^"]*"[^"]+"' /opt/Prometheus/vault/.vault-keys \
            | head -1 | sed -E 's/.*"([^"]+)"$/\1/')
        export VAULT_TOKEN
    fi
fi

if [ -z "${VAULT_TOKEN:-}" ]; then
    echo "launch-ticker: no VAULT_TOKEN (check /opt/Prometheus/vault/.vault-keys)" >&2
    exit 1
fi

# Fetch the shield API token from vault.
NEXUS_SHIELD_TOKEN=$(vault kv get -field=api_token secret/nexus-shield 2>/dev/null)
if [ -z "${NEXUS_SHIELD_TOKEN}" ]; then
    echo "launch-ticker: failed to read secret/nexus-shield from vault" >&2
    exit 1
fi
export NEXUS_SHIELD_TOKEN
export NEXUS_SHIELD_URL="${NEXUS_SHIELD_URL:-http://127.0.0.1:8080}"

exec /opt/NexusShield/target/release/security-ticker
