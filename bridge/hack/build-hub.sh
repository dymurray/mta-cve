#!/usr/bin/env bash
# Builds the customized MTA hub in-cluster from ~/git/mta-tackle2-hub and
# deploys it to deploy/mta-hub, pinned by digest.
#
# Revert to the stock hub:
#   kubectl -n openshift-mta set image deploy/mta-hub mta-hub=registry.redhat.io/mta/mta-hub-rhel9@sha256:76f433d71711b0c261da9eca6cc7174cff4aa8a99047edfed34d5a63949431f0
set -euo pipefail
source "$(dirname "$0")/env.sh"
HUB_DIR="${HUB_DIR:-$HOME/git/mta-tackle2-hub}"
STOCK_HUB="registry.redhat.io/mta/mta-hub-rhel9@sha256:76f433d71711b0c261da9eca6cc7174cff4aa8a99047edfed34d5a63949431f0"

# 1. Migration guard: refuse to deploy a source tree whose schema
#    migrations exceed the deployed image's (the custom hub must remain a
#    one-line revert to stock).
src_v=$(ls "$HUB_DIR/internal/migration" | grep -E '^v[0-9]+$' | sed 's/^v//' | sort -n | tail -1)
dep_v=$(k -n "$MTA_NS" exec deploy/mta-hub -c mta-hub -- sh -c \
  'ls /database/migration 2>/dev/null | sed "s/^v//" | grep -E "^[0-9]+$" | sort -n | tail -1')
echo "migrations: source v${src_v:-none}, deployed v${dep_v:-none}"
if [[ -z "$src_v" || -z "$dep_v" ]]; then
  echo "ERROR: could not determine migration levels" >&2
  exit 1
fi
if (( src_v > dep_v )); then
  echo "ERROR: source migrations (v${src_v}) exceed the deployed database (v${dep_v}); refusing to deploy" >&2
  exit 1
fi

# 2. Archive the hub source with our Dockerfile at the archive root.
#    The repo's own Dockerfile/konflux.Dockerfile are excluded so the
#    custom one (images/hub/Dockerfile) is the one the build uses.
cd "$HUB_DIR"
COPYFILE_DISABLE=1 tar --no-mac-metadata --no-xattrs \
  --exclude='./.git' --exclude='./bin' \
  --exclude='./Dockerfile' --exclude='./konflux.Dockerfile' \
  -cf /tmp/hub-src.tar .
tar -rf /tmp/hub-src.tar -C "$BRIDGE_ROOT/images/hub" Dockerfile
gzip -f /tmp/hub-src.tar

# 3. Build.
oc --context="$KCTX" -n "$MTA_NS" start-build mta-hub-custom --from-archive=/tmp/hub-src.tar.gz --follow --wait

# 4. Pin by digest and deploy.
digest=$(oc --context="$KCTX" -n "$MTA_NS" get istag mta-hub-custom:latest -o jsonpath='{.image.metadata.name}')
img="image-registry.openshift-image-registry.svc:5000/${MTA_NS}/mta-hub-custom@${digest}"
container=$(k -n "$MTA_NS" get deploy mta-hub -o jsonpath='{.spec.template.spec.containers[0].name}')
k -n "$MTA_NS" set image deploy/mta-hub "${container}=${img}"

# 5. Rollout.
k -n "$MTA_NS" rollout status deploy/mta-hub --timeout=600s

echo
echo "Deployed ${img}"
echo "Revert with:"
echo "  kubectl -n ${MTA_NS} set image deploy/mta-hub ${container}=${STOCK_HUB}"
