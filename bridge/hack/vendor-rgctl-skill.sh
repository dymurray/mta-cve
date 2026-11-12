#!/usr/bin/env bash
# Vendors skills/rgctl from the rgctl repo at a tag into images/skills/rgctl,
# moving top-level frontmatter fields the Agent Skills spec does not allow
# (rgctl-managed) under metadata so the agentic skill loader accepts it.
# Usage: hack/vendor-rgctl-skill.sh v0.4.21 [path-to-rgctl-checkout]
set -euo pipefail
tag="${1:?tag}"; src="${2:-$HOME/git/rgctl}"
dest="$(cd "$(dirname "$0")/.." && pwd)/images/skills"
git -C "$src" fetch -q --tags
rm -rf "$dest/rgctl"
git -C "$src" archive "$tag" skills/rgctl | tar -x -C "$dest" --strip-components=1
python3 - "$dest/rgctl/SKILL.md" "$tag" <<'PY'
import re, sys
p, tag = sys.argv[1], sys.argv[2]
s = open(p).read()
m = re.match(r'^---\n(.*?)\n---\n', s, re.S)
fm = m.group(1).replace('rgctl-managed: true',
    'metadata:\n  rgctl-managed: "true"\n  source: https://github.com/sshaaf/rgctl/tree/%s/skills/rgctl' % tag)
open(p, 'w').write('---\n' + fm + '\n---\n' + s[m.end():])
PY
echo "vendored rgctl skill $tag into $dest/rgctl"
