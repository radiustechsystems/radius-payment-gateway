#!/usr/bin/env bash
# Copies the policy evaluator (the `policy` and `domain` crates) and the conformance vectors
# from a radius-platform checkout at a commit into this repository, so the gateway builds from a
# plain checkout with no access to the platform's repository. Re-run it to move to a newer
# platform commit; the stub workspace in vendor/radius-platform/Cargo.toml stays as it is.
#
#   scripts/vendor-platform.sh ../radius-platform [commit]
set -euo pipefail

platform="${1:?usage: $0 <radius-platform checkout> [commit]}"
commit="${2:-HEAD}"
here="$(cd "$(dirname "$0")/.." && pwd)"
dest="$here/vendor/radius-platform"
full="$(git -C "$platform" rev-parse --verify "$commit^{commit}")"

rm -rf "$dest/crates"
mkdir -p "$dest"
git -C "$platform" archive "$full" \
    crates/policy/Cargo.toml crates/policy/README.md crates/policy/src \
    crates/domain/Cargo.toml crates/domain/src \
    | tar -x -C "$dest"

# Test snapshots aren't needed to build the crates.
find "$dest/crates" -type d -name snapshots -prune -exec rm -rf {} +

# The crates' dev-dependencies (insta, proptest, the full alloy) aren't needed to build them and
# would have to be declared in the stub workspace; drop those sections.
for manifest in "$dest"/crates/*/Cargo.toml; do
    python3 - "$manifest" <<'PY'
import re, sys
path = sys.argv[1]
text = open(path).read()
text = re.sub(r"\n\[dev-dependencies\]\n(?:[^\[].*\n|\n)*", "\n", text)
open(path, "w").write(text.rstrip("\n") + "\n")
PY
done

rm -f "$here"/tests/vectors/*.json "$here/tests/vectors/README.md"
mkdir -p "$here/tests/vectors"
git -C "$platform" archive "$full" crates/policy/tests/vectors \
    | tar -x -C "$here/tests/vectors" --strip-components=4

echo "$full" > "$dest/COMMIT"
echo "$full" > "$here/tests/vectors/VECTORS_COMMIT"
echo "vendored radius-platform $full into vendor/radius-platform and tests/vectors"
