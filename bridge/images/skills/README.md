# Agent skills image

`rgctl/` is the rgctl skill from https://github.com/sshaaf/rgctl at tag
`v0.4.21` (`skills/rgctl`), unmodified except for its frontmatter. Upstream
sets `rgctl-managed: true` as a top-level field, which the agentic-controller
skill loader rejects: the Agent Skills spec allows only name, description,
license, compatibility, metadata and allowed-tools. Here that field lives
under `metadata`.

Refresh: `hack/vendor-rgctl-skill.sh <tag>`.
