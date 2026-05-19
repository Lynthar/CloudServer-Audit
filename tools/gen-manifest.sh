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
    HASH_CMD=(sha256sum)
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

# Strip CR before hashing so Windows checkouts (where Git Bash can
# leave CRLF in the working tree despite .gitattributes eol=lf, e.g.
# files staged before the attribute was added) produce the same hash
# as Linux. install.sh runs `sha256sum -c` on Linux targets only —
# files there are LF, so a CR-stripped hash matches the byte-for-byte
# hash on-disk. Sorted by path for stable diff output.
{
    for f in "${files[@]}"; do
        hash=$(tr -d '\r' < "$f" | "${HASH_CMD[@]}" | awk '{print $1}')
        printf '%s  %s\n' "$hash" "$f"
    done
} | sort -k 2 > manifest.sha256

echo "manifest.sha256 regenerated (${#files[@]} files)"
