#!/usr/bin/env bash
# Regenerate manifest.sha256.
#
# Lists SHA-256 hashes for every runtime-critical file shipped to
# users — the entry script, all of core/, all of modules/, and the
# installer scripts. Run this after any change to one of those
# files; CI fails if manifest.sha256 is out of sync.
#
# Files NOT covered: docs/, tests/, README*, LICENSE, .github/,
# .git*, manifest.sha256 itself. Those are either dev-time only
# or self-referential.
#
# Hash command auto-detected: sha256sum on Linux, shasum -a 256
# on macOS (both produce the GNU "<hash>  <path>" format that
# install.sh later passes to `sha256sum -c`).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if command -v sha256sum >/dev/null 2>&1; then
    # `--text` forces two-space (text-mode) output regardless of
    # platform. On Linux this is already the default and is a no-op;
    # on Git Bash for Windows the default is binary mode which emits
    # `<hash> *<path>` and breaks byte-for-byte equality with the
    # Linux-generated manifest, tripping the manifest-freshness CI
    # job even when contents are identical.
    HASH_CMD=(sha256sum --text)
elif command -v shasum >/dev/null 2>&1; then
    HASH_CMD=(shasum -a 256)
else
    echo "ERROR: need sha256sum (Linux coreutils) or shasum (macOS)" >&2
    exit 1
fi

files=()
files+=( vpssec install.sh run.sh )
while IFS= read -r f; do files+=("$f"); done < <(find core -type f \( -name '*.sh' -o -name '*.json' \) | sort)
while IFS= read -r f; do files+=("$f"); done < <(find modules -type f -name '*.sh' | sort)

# Sort by filename for stable diff output regardless of generation
# order. The leading hash is irrelevant to ordering since paths are
# unique.
"${HASH_CMD[@]}" "${files[@]}" | sort -k 2 > manifest.sha256

echo "manifest.sha256 regenerated (${#files[@]} files)"
