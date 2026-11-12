#!/usr/bin/env bash
# Builds the skills image (images/skills) in-cluster: the spec-conformant
# rgctl skill served to agents through SkillCard rgctl-osv.
set -euo pipefail
source "$(dirname "$0")/env.sh"
cd "$BRIDGE_ROOT/images/skills"
COPYFILE_DISABLE=1 tar --no-mac-metadata --no-xattrs -czf /tmp/skills-src.tgz .
oc --context "$KCTX" -n "$MTA_NS" start-build mta-cve-skills --from-archive=/tmp/skills-src.tgz --follow --wait
