#!/usr/bin/env bash
# Installs the MTA operator (public OLM build, channel MTA_CHANNEL) and the
# Tackle CR with the agentic API enabled. Idempotent.
set -euo pipefail
source "$(dirname "$0")/env.sh"
cd "$BRIDGE_ROOT"

MTA_CHANNEL="${MTA_CHANNEL:-8.3}"

k get namespace "$MTA_NS" >/dev/null 2>&1 || k create namespace "$MTA_NS"

# A namespace-scoped operator needs an OperatorGroup in its namespace.
k apply -f - <<EOF
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: mta
  namespace: $MTA_NS
EOF

k apply -f - <<EOF
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: mta-operator
  namespace: $MTA_NS
spec:
  channel: "$MTA_CHANNEL"
  name: mta-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

echo "Waiting for the MTA operator CSV to install..."
until k -n "$MTA_NS" get csv -o name 2>/dev/null | grep -q '^clusterserviceversion' ; do sleep 10; done
k -n "$MTA_NS" wait --for=jsonpath='{.status.phase}'=Succeeded csv/"$(k -n "$MTA_NS" get csv -o jsonpath='{.items[0].metadata.name}')" --timeout=600s

k apply -f - <<EOF
apiVersion: konveyor.tackle.io/v1alpha1
kind: Tackle
metadata:
  name: mta
  namespace: $MTA_NS
spec:
  agentic_enabled: true
EOF

echo "Waiting for the hub and the agentic controller..."
k -n "$MTA_NS" rollout status deploy/mta-hub --timeout=600s
k -n "$MTA_NS" rollout status deploy/agentic-controller --timeout=600s
k -n "$MTA_NS" rollout status deploy/mta-ui --timeout=600s
echo "MTA is up (channel $MTA_CHANNEL, agentic_enabled)."
