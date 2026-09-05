#!/usr/bin/env bash
# Verify that every relative Markdown link in the repository resolves to a file that exists.
#
# Scope: the root documents AND the 251-file docs/ site. Both matter, for different reasons:
#
#   * The root README shipped links to four documents that were not in the tree — including a
#     claimed SBOM. A newcomer's first act is to follow those links.
#   * docs/ shipped 243 broken internal links across 46 files. That went unnoticed through an
#     entire release-readiness audit precisely because an earlier version of this script only
#     looked at the root, so the docs site was never checked by the gate that was supposed to
#     cover it.
#
# Links are resolved relative to the file that contains them, which is what a Markdown renderer
# does. Skipped by design: absolute URLs (http/https/mailto), pure anchors, and GitHub-relative
# paths such as ../../security/advisories/new, which only resolve once the repo is hosted.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1

status=0
checked=0
broken=0

check_file() {
  local src="$1" dir
  dir="$(dirname "$src")"
  while IFS= read -r target; do
    [ -n "$target" ] || continue
    case "$target" in
      http://*|https://*|mailto:*|\#*|../../*) continue ;;
    esac
    local path="${target%%#*}"
    [ -n "$path" ] || continue
    checked=$((checked + 1))
    if [ ! -e "$dir/$path" ]; then
      echo "BROKEN: $src -> $target"
      broken=$((broken + 1))
      status=1
    fi
  done < <(grep -oE '\]\([^)[:space:]]+\)' "$src" | sed 's/^](//; s/)$//')

  # Also check HTML image references. Markdown files legitimately contain raw HTML — the README
  # uses a <picture> with the brand lockups — and `](...)` does not match `src=`/`srcset=`, so a
  # broken logo path would otherwise pass this gate silently.
  while IFS= read -r target; do
    [ -n "$target" ] || continue
    case "$target" in
      http://*|https://*|data:*|\#*|../../*) continue ;;
    esac
    local apath="${target%%#*}"
    [ -n "$apath" ] || continue
    checked=$((checked + 1))
    if [ ! -e "$dir/$apath" ]; then
      echo "BROKEN: $src -> $target (html asset)"
      broken=$((broken + 1))
      status=1
    fi
  done < <(grep -oE '(src|srcset)="[^"]+"' "$src" | sed 's/^[a-z]*="//; s/"$//')
}

for src in *.md; do
  [ -f "$src" ] && check_file "$src"
done
if [ -d docs ]; then
  # `.html` as well as `.md`: docs/index.html is the docs entry point and references the brand icon
  # and the vendored viewer scripts, none of which a Markdown-only scan would see.
  while IFS= read -r src; do check_file "$src"; done < <(find docs -name '*.md' -o -name '*.html' | sort)
fi

echo "doc links checked: $checked   broken: $broken"
[ "$status" -eq 0 ] && echo "doc links ok"
exit "$status"
