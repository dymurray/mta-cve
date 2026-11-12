# Common environment for the RHTPA + MTA CVE demo scripts.
export KUBECONFIG="${KUBECONFIG_DYLAN:-${KUBECONFIG:-$HOME/.kube/config}}"
export KCTX="${KCTX:-admin}"
export TPA_NS=trusted-profile-analyzer
export MTA_NS=openshift-mta
export APPS_DOMAIN=apps.mta-cve.mg.dog8code.com
export APP_DOMAIN="-${TPA_NS}.${APPS_DOMAIN}"
export SSO_HOST="sso${APP_DOMAIN}"
export TPA_HOST="server${APP_DOMAIN}"
k() { kubectl --context="$KCTX" "$@"; }
# Resolve the repo root under both bash and zsh.
if [[ -n "${BASH_SOURCE[0]:-}" ]]; then _here="${BASH_SOURCE[0]}"; else _here="${(%):-%x}"; fi
export BRIDGE_ROOT="$(cd "$(dirname "$_here")/.." && pwd)"
SECRETS_FILE="$BRIDGE_ROOT/.secrets.env"
if [[ ! -f "$SECRETS_FILE" ]]; then
  {
    echo "PG_ADMIN_PASSWORD=$(openssl rand -hex 16)"
    echo "PG_TRUSTIFY_PASSWORD=$(openssl rand -hex 16)"
    echo "PG_KEYCLOAK_PASSWORD=$(openssl rand -hex 16)"
    echo "KC_ADMIN_PASSWORD=$(openssl rand -hex 12)"
    echo "TPA_ADMIN_PASSWORD=$(openssl rand -hex 8)"
    echo "CLI_CLIENT_SECRET=$(uuidgen | tr 'A-Z' 'a-z')"
  } > "$SECRETS_FILE"
  chmod 600 "$SECRETS_FILE"
fi
set -a; . "$SECRETS_FILE"; set +a
