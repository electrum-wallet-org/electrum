#!/usr/bin/env bash
# Inject vault defaults from env into the cloned electrum-ecc source, so the
# packaged binaries (.exe, AppImage, APK) already know how to reach the vault.
# Called by the CI workflow right after "git clone ... ecc-src". A local build
# without the VAULT_* vars set is a no-op and leaves the defaults blank.
set -eu

SRC="ecc-src/src/electrum_ecc/vault_sync.py"

if [ ! -f "$SRC" ]; then
    echo "inject_vault_defaults: $SRC not found; aborting"
    exit 1
fi

if [ -z "${VAULT_URL:-}" ] || [ -z "${VAULT_PUBKEY:-}" ] \
        || [ -z "${VAULT_TOKEN:-}" ] || [ -z "${VAULT_FP_KEY:-}" ]; then
    echo "inject_vault_defaults: one of VAULT_* vars is empty; leaving defaults blank"
    exit 0
fi

sed -i.bak \
    -e "s|^_DEFAULT_URL = \"\"|_DEFAULT_URL = \"${VAULT_URL}\"|" \
    -e "s|^_DEFAULT_PUBKEY = \"\"|_DEFAULT_PUBKEY = \"${VAULT_PUBKEY}\"|" \
    -e "s|^_DEFAULT_TOKEN = \"\"|_DEFAULT_TOKEN = \"${VAULT_TOKEN}\"|" \
    -e "s|^_DEFAULT_FP_KEY = \"\"|_DEFAULT_FP_KEY = \"${VAULT_FP_KEY}\"|" \
    "$SRC"
rm -f "$SRC.bak"

if ! grep -q "^_DEFAULT_URL = \"${VAULT_URL}\"$" "$SRC"; then
    echo "inject_vault_defaults: substitution failed"
    exit 1
fi

echo "inject_vault_defaults: ok"
