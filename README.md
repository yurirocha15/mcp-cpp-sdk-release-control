# mcp-cpp-sdk ConanCenter release control

This public repository turns one signed, immutable mcp-cpp-sdk GitHub Release
into a ConanCenter recipe branch on
[`yurirocha15/conan-center-index`](https://github.com/yurirocha15/conan-center-index).
The maintainer opens the ConanCenter pull request from that branch; this
repository holds no credential for `conan-io/conan-center-index`.

The source release workflow dispatches `conan-center-pr.yml` through the
asset-free immutable GitHub Release tag `release-control-v1` with eight bounded
inputs. The first job holds no credential. It requires that exact tag, its
commit, and the tagged workflow identity, then verifies the source repository,
the completed source run, the immutable release, every signed asset, the
signed publication contract, and the OpenPGP-signed source tag.

From the signed recipe inputs it assembles `recipes/mcp-cpp-sdk` on the
current upstream `master`. A first submission reproduces the recipe tree that
the source release validated. A later version is added to the upstream recipe
only when that recipe still has the exact layout written here; anything else
fails closed for manual resolution.

The second job runs in the protected `conan-fork-push` environment, which
accepts only the control tag. It uses a GitHub App installed only on the fork
with contents write to create a single commit on the verified upstream base
and a `package/mcp-cpp-sdk-<version>` branch. It reads the branch back,
accepts an existing branch only when it already holds the identical recipe,
and ends with a compare link that prefills the ConanCenter pull request.

`repository-settings.json` names the required public controls, checks,
variables, secret, and App grant without storing operator identities, numeric
IDs, fingerprints, or provisioning evidence.
