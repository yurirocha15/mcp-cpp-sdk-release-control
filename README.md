# mcp-cpp-sdk ConanCenter release control

This public repository is the hardened approval broker for opening one
ConanCenter recipe pull request. It is not a general GitHub API proxy.

The dispatch accepts exactly eleven bounded strings. Public verification polls a
manual source release for up to one hour, then verifies the immutable release,
recipe tree, and exact open upstream authorization issue before the protected
environment. The protected publisher client is transferred in an
attempt-specific, checksum-bound artifact retained for 90 days. The PAT job
does not checkout or execute source or recipe content, and exposes the PAT only
to its final fixed-route standard-library client step.

The final client only performs fixed GitHub API GETs and, when no identical PR
exists, one fixed POST to `conan-io/conan-center-index`. Immediately before
that POST it rechecks the exact issue number, IDs, author, creation time, body
digest, `library request` label, title, and open state, then snapshots the
upstream recipe tree as the final read. The returned PR must use that exact base
commit. It rejects redirects, pagination, oversized bodies, ambiguous PRs,
identity mismatches, recovery branch misuse, and every caller-supplied URL. PR
titles and bodies follow the current ConanCenter contribution templates for new
recipes and later versions.

Publishing is dispatched only through the asset-free immutable GitHub Release
tag `release-control-v1`. A credential-free first job requires that exact tag,
its immutable commit SHA supplied by the source preflight, and the exact tagged
workflow identity. The protected environment accepts only that tag; the tag
ruleset blocks updates and deletion without bypass actors.

`repository-settings.json` names the required public controls, checks,
variables, and secret without storing operator identities, numeric IDs,
fingerprints, or provisioning evidence. Operational setup remains outside this
tracked repository.
