#!/usr/bin/env bash
# Guard the one mistake that silently breaks diagrams in the documentation viewer.
#
# docs/index.html renders Markdown with `marked`, then hands each diagram's `textContent` to
# mermaid. An HTML entity written inside a ```mermaid block (`&#58;` for ':', `&#59;` for ';') is
# DECODED by marked before mermaid ever sees it, so the raw character reappears and breaks the
# stateDiagram / sequenceDiagram grammar — which treats ':' and ';' as delimiters.
#
# The symptom is invisible to a Markdown linter and to `mermaid.parse()` on the raw source: it only
# appears in the browser, as "Error rendering diagram". Five documents shipped this way.
#
# The fix, and the rule this script enforces: use mermaid's OWN numeric escape (`#58;`, `#59;`),
# which is not HTML, so marked leaves it alone and mermaid decodes it itself.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1

status=0
found=0

while IFS= read -r file; do
  # Extract mermaid fenced blocks and report any HTML entity inside one.
  awk -v F="$file" '
    /^[[:space:]]*```[[:space:]]*mermaid[[:space:]]*$/ { inblk=1; next }
    inblk && /^[[:space:]]*```[[:space:]]*$/           { inblk=0; next }
    inblk && /&#[0-9]+;/ { printf "%s:%d: %s\n", F, NR, $0 }
  ' "$file"
done < <(find . -name '*.md' -not -path './target/*' | sort) > /tmp/mermaid-entities.$$

if [ -s /tmp/mermaid-entities.$$ ]; then
  echo "HTML entities found inside mermaid blocks — marked will decode these and break the diagram."
  echo "Use mermaid's numeric escape instead: &#58; -> #58;   &#59; -> #59;"
  echo
  cat /tmp/mermaid-entities.$$
  found=$(wc -l < /tmp/mermaid-entities.$$ | tr -d ' ')
  status=1
fi
rm -f /tmp/mermaid-entities.$$

blocks=$(grep -rc '^[[:space:]]*```[[:space:]]*mermaid' --include='*.md' . 2>/dev/null \
         | grep -v '^./target' | awk -F: '{s+=$2} END{print s+0}')
echo "mermaid blocks scanned: $blocks   offending lines: $found"
[ "$status" -eq 0 ] && echo "mermaid escaping ok"
exit "$status"
