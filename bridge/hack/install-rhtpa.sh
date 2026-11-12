#!/usr/bin/env bash
# Installs RHTPA (Helm chart 3.1.1) with RHBK + PostgreSQL in trusted-profile-analyzer.
# Idempotent; credentials are generated into .secrets.env on first run.
set -euo pipefail
source "$(dirname "$0")/env.sh"
cd "$BRIDGE_ROOT/deploy/rhtpa"
s() { k -n "$TPA_NS" create secret generic "$@" --dry-run=client -o yaml | k apply -f -; }
k apply -f 00-namespace-rhbk.yaml
until k -n "$TPA_NS" get csv -o name 2>/dev/null | grep -q rhbk; do sleep 5; done
k -n openshift-ingress-operator get secret router-ca -o jsonpath='{.data.tls\.crt}' | base64 -d > /tmp/router-ca.crt
k -n "$TPA_NS" create configmap rhtpa-trust-anchor --from-file=tls.crt=/tmp/router-ca.crt --dry-run=client -o yaml | k apply -f -
s postgresql-bootstrap --from-literal=admin-password="$PG_ADMIN_PASSWORD" --from-literal=keycloak-password="$PG_KEYCLOAK_PASSWORD"
s keycloak-db --from-literal=username=keycloak --from-literal=password="$PG_KEYCLOAK_PASSWORD"
s keycloak-bootstrap-admin --from-literal=username=temp-admin --from-literal=password="$KC_ADMIN_PASSWORD"
s postgresql-credentials --from-literal=db.host=postgresql --from-literal=db.port=5432 --from-literal=db.name=trustify --from-literal=db.user=trustify --from-literal=db.password="$PG_TRUSTIFY_PASSWORD"
s postgresql-admin-credentials --from-literal=db.host=postgresql --from-literal=db.port=5432 --from-literal=db.name=postgres --from-literal=db.user=postgres --from-literal=db.password="$PG_ADMIN_PASSWORD"
s oidc-cli --from-literal=client-secret="$CLI_CLIENT_SECRET"
s rhtpa-admin --from-literal=username=admin --from-literal=password="$TPA_ADMIN_PASSWORD"
k apply -f 10-postgresql.yaml -f 15-storage-pvc.yaml -f 20-keycloak.yaml
k -n "$TPA_NS" wait keycloak/sso --for=condition=Ready --timeout=600s
k apply -f 30-realm.yaml
helm repo add openshift-helm-charts https://charts.openshift.io/ >/dev/null 2>&1 || true
helm --kube-context "$KCTX" upgrade --install redhat-trusted-profile-analyzer \
  openshift-helm-charts/redhat-trusted-profile-analyzer --version 3.1.1 -n "$TPA_NS" \
  -f values-rhtpa.yaml -f values-importers.yaml --set-string appDomain="$APP_DOMAIN" --wait --timeout 15m
echo "RHTPA: https://$TPA_HOST  (admin / \$TPA_ADMIN_PASSWORD in .secrets.env)"
