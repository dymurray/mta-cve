#!/usr/bin/env bash
# Builds the customized MTA UI in-cluster from the ~/git/mta-tackle2-ui-cve worktree.
set -euo pipefail
source "$(dirname "$0")/env.sh"
UI_DIR="${UI_DIR:-$HOME/git/mta-tackle2-ui-cve}"
cd "$UI_DIR"
COPYFILE_DISABLE=1 tar --no-mac-metadata --no-xattrs --exclude='./node_modules' --exclude='./client/node_modules' \
  --exclude='./server/node_modules' --exclude='./common/node_modules' --exclude='./dist' --exclude='./.git' \
  --exclude='./cypress' -czf /tmp/ui-src.tgz .
oc --context="$KCTX" -n "$MTA_NS" start-build mta-ui-cve --from-archive=/tmp/ui-src.tgz --follow --wait
# The operator deploys the UI with imagePullPolicy IfNotPresent, so pin the
# Tackle CR to the new digest (a moving :latest tag would keep the cached image).
digest=$(oc --context="$KCTX" -n "$MTA_NS" get istag mta-ui-cve:latest -o jsonpath='{.image.metadata.name}')
img="image-registry.openshift-image-registry.svc:5000/${MTA_NS}/mta-ui-cve@${digest}"
k -n "$MTA_NS" patch tackle mta --type merge -p "{\"spec\":{\"ui_image_fqin\":\"${img}\"}}"
echo "Tackle CR ui_image_fqin -> ${img}"
# Wait for the operator to roll the new digest out. When the operator is
# scaled down nothing reconciles the CR, so set the deployment image directly.
if [[ "$(k -n "$MTA_NS" get deploy mta-operator -o jsonpath='{.spec.replicas}' 2>/dev/null)" == "0" ]]; then
  echo "mta-operator is scaled to 0; updating deploy/mta-ui directly"
  k -n "$MTA_NS" set image deploy/mta-ui "$(k -n "$MTA_NS" get deploy mta-ui -o jsonpath='{.spec.template.spec.containers[0].name}')=$img"
fi
for _ in $(seq 1 60); do
  [[ "$(k -n "$MTA_NS" get deploy mta-ui -o jsonpath='{.spec.template.spec.containers[0].image}')" == "$img" ]] && break
  sleep 10
done
k -n "$MTA_NS" rollout status deploy/mta-ui --timeout=300s
