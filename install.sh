#!/usr/bin/env bash
# AiNxt OS — prebuilt binary installer.
# README usage:
#   curl -fsSL https://raw.githubusercontent.com/npci/ainxt-os/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/npci/ainxt-os/main/install.sh | bash -s 0.2.0
set -euo pipefail

REPO="npci/ainxt-os"
BASE_DIR="${AINXT_HOME:-$HOME/.ainxt-os}"
BIN_DIR="$BASE_DIR/bin"
CONFIG="$BASE_DIR/runtimed.toml"
VERSION="${1:-}"
LOCAL_MODE="false"
if [ "${1:-}" = "--local" ]; then
  LOCAL_MODE="true"
  VERSION=""
fi
TMP=""

say() { printf 'AiNxt OS: %s\n' "$*"; }
fatal() { printf 'AiNxt OS: ERROR: %s\n' "$*" >&2; exit 1; }
cleanup() { [ -z "${TMP:-}" ] || rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

command -v curl >/dev/null 2>&1 || fatal "curl is required."
command -v uname >/dev/null 2>&1 || fatal "uname is required."

OS="$(uname -s 2>/dev/null || true)"
ARCH="$(uname -m 2>/dev/null || true)"

case "$OS" in
  Darwin) PLATFORM="macos"; OS_RE='(macos|darwin|osx)' ;;
  Linux) PLATFORM="linux"; OS_RE='linux' ;;
  MINGW*|MSYS*|CYGWIN*) PLATFORM="windows"; OS_RE='(windows|win)' ;;
  *) fatal "unsupported operating system '$OS'. Supported: macOS, Linux, and Windows/Git Bash." ;;
esac

case "$ARCH" in
  x86_64|amd64|AMD64) ARCH="x86_64"; ARCH_RE='(x86_64|amd64|x64)' ;;
  arm64|aarch64|ARM64) ARCH="arm64"; ARCH_RE='(arm64|aarch64|arm64-v8a)' ;;
  *) fatal "unsupported architecture '$ARCH'. Supported: x86_64 and arm64." ;;
esac

mkdir -p "$BASE_DIR"
TMP="$(mktemp -d 2>/dev/null || mktemp -d -t ainxt-install)"
RELEASE_JSON="$TMP/release.json"

# Local test mode: when invoked as `bash ./install.sh --local`, use the binaries
# next to this script instead of querying GitHub Releases. This is intentionally
# opt-in and does not affect the README production install command.
if [ "$LOCAL_MODE" = "true" ]; then
  SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  CONSOLE_SOURCE="$SCRIPT_DIR/ainxt-os"
  RUNTIME_SOURCE="$SCRIPT_DIR/ainxt-runtimed"
  [ -f "$CONSOLE_SOURCE" ] || fatal "local install requires '$CONSOLE_SOURCE'."
  [ -f "$RUNTIME_SOURCE" ] || fatal "local install requires '$RUNTIME_SOURCE'."
  [ -x "$CONSOLE_SOURCE" ] || fatal "local console '$CONSOLE_SOURCE' is not executable."
  [ -x "$RUNTIME_SOURCE" ] || fatal "local runtime '$RUNTIME_SOURCE' is not executable."
  say "installing local macos/$ARCH binaries from $SCRIPT_DIR"
else
# README supports an optional version argument. Accept both v0.2.0 and 0.2.0 tags.
if [ -n "$VERSION" ]; then
  TAG="v${VERSION#v}"
  if ! curl -fsSL -H 'Accept: application/vnd.github+json' \
      "https://api.github.com/repos/$REPO/releases/tags/$TAG" -o "$RELEASE_JSON"; then
    TAG="${VERSION#v}"
    curl -fsSL -H 'Accept: application/vnd.github+json' \
      "https://api.github.com/repos/$REPO/releases/tags/$TAG" -o "$RELEASE_JSON" \
      || fatal "could not find GitHub release '$VERSION'."
  fi
else
  curl -fsSL -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/$REPO/releases/latest" -o "$RELEASE_JSON" \
    || fatal "could not query the latest GitHub release for $REPO."
fi

# Discover the platform asset instead of depending on one exact filename. The archive name must
# identify both OS and architecture; after download we also verify that it contains BOTH binaries.
asset_urls() {
  grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' "$RELEASE_JSON" \
    | sed -E 's/.*"(https:[^"]+)"/\1/'
}

ASSET_URL=""
while IFS= read -r url; do
  [ -n "$url" ] || continue
  name="${url##*/}"
  lower="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')"
  if printf '%s\n' "$lower" | grep -Eq "$OS_RE" \
      && printf '%s\n' "$lower" | grep -Eq "$ARCH_RE" \
      && printf '%s\n' "$lower" | grep -Eq '\.(tar\.gz|tgz|zip)$'; then
    ASSET_URL="$url"
    break
  fi
done < <(asset_urls)

[ -n "$ASSET_URL" ] || fatal "no prebuilt $PLATFORM/$ARCH release asset was found. The GitHub Release must publish an archive containing ainxt-os and ainxt-runtimed."

ASSET_NAME="${ASSET_URL##*/}"
say "installing $PLATFORM/$ARCH from ${VERSION:-latest} ($ASSET_NAME)"

ARCHIVE="$TMP/$ASSET_NAME"
EXTRACT="$TMP/extract"
mkdir -p "$EXTRACT"
curl -fL --retry 3 --retry-delay 1 --proto '=https' --tlsv1.2 "$ASSET_URL" -o "$ARCHIVE" \
  || fatal "download failed: $ASSET_URL"

case "$ARCHIVE" in
  *.tar.gz|*.tgz)
    command -v tar >/dev/null 2>&1 || fatal "tar is required to extract $ASSET_NAME."
    tar -xzf "$ARCHIVE" -C "$EXTRACT"
    ;;
  *.zip)
    if command -v unzip >/dev/null 2>&1; then
      unzip -q "$ARCHIVE" -d "$EXTRACT"
    elif command -v powershell.exe >/dev/null 2>&1; then
      powershell.exe -NoProfile -NonInteractive -Command \
        "Expand-Archive -LiteralPath '$ARCHIVE' -DestinationPath '$EXTRACT' -Force"
    else
      fatal "cannot extract $ASSET_NAME: install unzip or use PowerShell."
    fi
    ;;
  *) fatal "unsupported release archive format: $ASSET_NAME" ;;
esac

CONSOLE_SOURCE="$(find "$EXTRACT" -type f \( -name ainxt-os -o -name ainxt-os.exe \) -print -quit)"
RUNTIME_SOURCE="$(find "$EXTRACT" -type f \( -name ainxt-runtimed -o -name ainxt-runtimed.exe \) -print -quit)"
[ -n "$CONSOLE_SOURCE" ] || fatal "release archive '$ASSET_NAME' does not contain ainxt-os."
[ -n "$RUNTIME_SOURCE" ] || fatal "release archive '$ASSET_NAME' does not contain ainxt-runtimed."
fi

mkdir -p "$BIN_DIR"

# The Console defaults to a relative runtimed.toml. The README says users can simply run
# `ainxt-os` after installation, so the launcher below starts the real binary from ~/.ainxt-os.
# This also keeps .ainxt-console state and the config in one predictable per-user directory.
if [ ! -f "$CONFIG" ]; then
  if [ "$LOCAL_MODE" = "true" ]; then
    EXAMPLE="$(find "$SCRIPT_DIR" -type f -name 'runtimed.example.toml' -print -quit || true)"
  else
    EXAMPLE="$(find "$EXTRACT" -type f -path '*/runtimed.example.toml' -print -quit || true)"
  fi
  if [ -n "$EXAMPLE" ]; then
    cp "$EXAMPLE" "$CONFIG"
  else
    cat > "$CONFIG" <<'TOML'
version = 1

[server]
host = "127.0.0.1"
port = 8080

[session]
max_sessions = 4096
inbox_capacity = 8
idle_ttl_ms = 300000
turn_timeout_ms = 300000

[gates]
compliance = "default"
authz = "rbac"
audit = "memory"

[limits]
max_agent_iters = 4
stream_channel_bound = 64
max_input_bytes = 1000000
provider_max_retries = 2
provider_backoff_base_ms = 20

[guardrails]
jailbreak = "audit"
groundedness = "audit"
toxicity = "audit"
system_prompt_leak = "audit"
citation = "audit"

[injection]
mode = "enforce"
TOML
  fi
fi
chmod 600 "$CONFIG" 2>/dev/null || true

if [ "$PLATFORM" = windows ]; then
  REAL_CONSOLE="$BIN_DIR/ainxt-os.exe"
  RUNTIME="$BIN_DIR/ainxt-runtimed.exe"
  LAUNCHER="$BIN_DIR/ainxt-os"
else
  REAL_CONSOLE="$BIN_DIR/ainxt-os.bin"
  RUNTIME="$BIN_DIR/ainxt-runtimed"
  LAUNCHER="$BIN_DIR/ainxt-os"
fi

cp "$CONSOLE_SOURCE" "$REAL_CONSOLE"
cp "$RUNTIME_SOURCE" "$RUNTIME"
chmod +x "$REAL_CONSOLE" "$RUNTIME" 2>/dev/null || true

cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
cd "${BASE_DIR}" || exit 1
exec "${REAL_CONSOLE}" --config "${CONFIG}" "\$@"
EOF
chmod +x "$LAUNCHER"

# Persist PATH without replacing a user's shell configuration. The current installer process also
# exports the path, so the command can be used immediately when the installer is sourced/executed.
PATH_LINE='export PATH="$HOME/.ainxt-os/bin:$PATH"'
add_path() {
  local file="$1"
  [ -n "$file" ] || return 0
  touch "$file" 2>/dev/null || return 0
  if ! grep -Fqx "$PATH_LINE" "$file" 2>/dev/null; then
    printf '\n# AiNxt OS\n%s\n' "$PATH_LINE" >> "$file"
  fi
}

case "${SHELL:-}" in
  */zsh) add_path "$HOME/.zshrc" ;;
  */bash) add_path "$HOME/.bashrc" ;;
  *)
    if [ -f "$HOME/.zshrc" ]; then add_path "$HOME/.zshrc"; else add_path "$HOME/.bashrc"; fi
    ;;
esac

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) export PATH="$BIN_DIR:$PATH" ;;
esac

say "installed to $BASE_DIR"
say "configuration: $CONFIG"
say "run: ainxt-os"
say "the Console starts ainxt-runtimed automatically and opens http://127.0.0.1:8081"
say "open a new terminal if ~/.ainxt-os/bin is not yet in your current PATH"
