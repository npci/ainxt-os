#!/usr/bin/env bash
#
# AiNxt OS — first-run setup.
#
# Contract (as documented in README.md "Quick start"):
#   ./setup.sh          verify prerequisites, build AiNxt OS and its Console, create runtimed.toml
#                       from the shipped example, validate it, print what to run next
#   ./setup.sh --check  inspect prerequisites only; change nothing
#   ./setup.sh --run    do all of the above, then open the AiNxt OS Console in a browser
#
# Safe to re-run: it never overwrites an existing runtimed.toml and never reinstalls a toolchain.
set -euo pipefail

cd "$(dirname "$0")"

RUST_FLOOR_MINOR=94          # workspace rust-version = "1.94"
DISK_REQUIRED_GB=5           # target/release measures 1.7 GB; 5 GB leaves room for the build itself.
DISK_TESTS_GB=45             # `cargo test --workspace` links a test binary per crate: ~40 GB in
                             # target/debug. Warned about, not required — most people never run it.
CONFIG=runtimed.toml
EXAMPLE=crates/ainxt-runtimed/config/runtimed.example.toml
BIN=./target/release/ainxt-runtimed
CONSOLE=./target/release/ainxt-os

MODE=install
case "${1:-}" in
  --check) MODE=check ;;
  --run)   MODE=run ;;
  -h|--help)
    # Print the header comment block (everything after the shebang up to the first
    # non-comment line), with the leading '# ' stripped.
    awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"
    exit 0 ;;
  "") ;;
  *)
    echo "setup.sh: unknown option '$1' (expected --check, --run or no argument)" >&2
    exit 2 ;;
esac

ok()   { printf '  \033[32mok\033[0m    %s\n' "$1"; }
warn() { printf '  \033[33mwarn\033[0m  %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }

failures=0

echo "AiNxt OS — checking prerequisites"

# ---- Rust -------------------------------------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  bad "cargo not found. Install Rust via https://rustup.rs, then re-run."
  failures=$((failures + 1))
else
  rustc_version=$(rustc --version 2>/dev/null | awk '{print $2}')
  minor=$(printf '%s' "$rustc_version" | cut -d. -f2)
  major=$(printf '%s' "$rustc_version" | cut -d. -f1)
  if [ "$major" -gt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -ge "$RUST_FLOOR_MINOR" ]; }; then
    ok "rustc $rustc_version (workspace floor is 1.$RUST_FLOOR_MINOR)"
  else
    bad "rustc $rustc_version is below the workspace floor 1.$RUST_FLOOR_MINOR. Run: rustup update"
    failures=$((failures + 1))
  fi
  # rust-toolchain.toml pins an exact toolchain; rustup fetches it on first use. Say so, because
  # otherwise the first build appears to hang while it downloads.
  if [ -f rust-toolchain.toml ] && command -v rustup >/dev/null 2>&1; then
    pinned=$(awk -F'"' '/^channel/ {print $2}' rust-toolchain.toml)
    if [ -n "${pinned:-}" ]; then
      if rustup toolchain list 2>/dev/null | grep -q "^$pinned"; then
        ok "pinned toolchain $pinned is installed"
      else
        warn "pinned toolchain $pinned is not installed yet — rustup will fetch it on first build"
      fi
    fi
  fi
fi

# ---- C toolchain ------------------------------------------------------------------------------
# ring, wasmtime and the tree-sitter crates all compile native code.
if command -v cc >/dev/null 2>&1 && cc --version >/dev/null 2>&1; then
  ok "C toolchain present ($(command -v cc))"
else
  bad "no working 'cc'. macOS: xcode-select --install. Debian/Ubuntu: apt install build-essential"
  failures=$((failures + 1))
fi

# ---- Disk -------------------------------------------------------------------------------------
avail_kb=$(df -Pk . 2>/dev/null | awk 'NR==2 {print $4}')
if [ -n "${avail_kb:-}" ]; then
  avail_gb=$((avail_kb / 1024 / 1024))
  if [ "$avail_gb" -ge "$DISK_REQUIRED_GB" ]; then
    ok "${avail_gb} GB free (need ~${DISK_REQUIRED_GB} GB to build and run AiNxt OS)"
    if [ "$avail_gb" -lt "$DISK_TESTS_GB" ]; then
      # Not a failure: building and running AiNxt OS is what this script is for. But a linker
      # ENOSPC reports `ld: write() failed, errno=28` and never mentions disk, so say it up front.
      warn "the full test suite (cargo test --workspace) needs ~${DISK_TESTS_GB} GB and would run out here"
    fi
  else
    bad "${avail_gb} GB free; ~${DISK_REQUIRED_GB} GB needed to build AiNxt OS"
    failures=$((failures + 1))
  fi
else
  warn "could not determine free disk space"
fi

# ---- Shipped files this script depends on -----------------------------------------------------
if [ -f "$EXAMPLE" ]; then
  ok "example config present ($EXAMPLE)"
else
  bad "missing $EXAMPLE — cannot create $CONFIG"
  failures=$((failures + 1))
fi
if [ -f Cargo.lock ]; then
  ok "Cargo.lock present — the build will use the locked dependency set"
else
  warn "Cargo.lock is absent; the build will resolve fresh versions and will NOT be reproducible"
fi

if [ "$failures" -gt 0 ]; then
  echo
  echo "setup.sh: $failures prerequisite check(s) failed. Nothing was changed."
  exit 1
fi

if [ "$MODE" = check ]; then
  echo
  echo "All prerequisites satisfied. Nothing was changed (--check)."
  exit 0
fi

# ---- Build ------------------------------------------------------------------------------------
echo
echo "Building AiNxt OS and its Console (release). The first build fetches ~328 crates and takes a while."
if [ -f Cargo.lock ]; then
  cargo build --locked --release -p ainxt-runtimed -p ainxt-console
else
  cargo build --release -p ainxt-runtimed -p ainxt-console
fi
ok "built $BIN"
ok "built $CONSOLE (the Console)"

# ---- Configure --------------------------------------------------------------------------------
if [ -f "$CONFIG" ]; then
  ok "$CONFIG already exists — left untouched"
else
  cp "$EXAMPLE" "$CONFIG"
  ok "created $CONFIG from $EXAMPLE"
fi

# ---- Validate ---------------------------------------------------------------------------------
# The daemon refuses to start until an identity posture is chosen. trusted-gateway is asserted here
# ONLY to validate the config; it is safe for --check because nothing is served. Read the note the
# script prints below before exposing a listener.
echo
echo "Validating the configuration (--check, not serving)"
if AINXT_TRUSTED_GATEWAY=1 "$BIN" --config "$CONFIG" --check >/tmp/ainxt-setup-check.$$ 2>&1; then
  ok "config OK"
  rm -f /tmp/ainxt-setup-check.$$
else
  bad "configuration did not validate:"
  tail -20 /tmp/ainxt-setup-check.$$ >&2
  rm -f /tmp/ainxt-setup-check.$$
  exit 1
fi

# ---- What to run next -------------------------------------------------------------------------
cat <<NEXT

Setup complete.

  The easiest way to use AiNxt OS — a chat window in your browser:

      $CONSOLE

  It starts AiNxt OS for you, opens a browser, and lets you choose a model and change
  settings without editing any files. Nothing else to install.

  ----------------------------------------------------------------------------------------

  If you are integrating AiNxt OS behind your own front end instead, run it directly:

      AINXT_TRUSTED_GATEWAY=1 $BIN --config $CONFIG

  then verify a governed turn:

      curl -N http://127.0.0.1:8080/v1/chat \\
        -H 'content-type: application/json' \\
        -H 'X-AInxt-User: alice' -H 'X-AInxt-Role: engineer' \\
        -H 'X-AInxt-Department: engineering' -H 'X-AInxt-Caps: chat.send' \\
        -H 'X-AInxt-Clearance: public' \\
        -d '{"session":"c1","turn":"t1","input":"hello","data_class":"public"}'

  Expect HTTP 200 and a stream ending in "turn.completed". The reply
  "offline mode: no model configured." is correct before you connect a model.

  AINXT_TRUSTED_GATEWAY=1 asserts that AiNxt OS is reachable ONLY through a gateway that has
  already authenticated the caller, because in that mode it believes the X-AInxt-* headers above.
  Never expose that listener to a browser. The Console exists precisely so you do not have to:
  it is the authenticating gateway, and it runs AiNxt OS in jwt-sso mode instead.
  See README "Decide how identity is established" and DOCKING.md.
NEXT

if [ "$MODE" = run ]; then
  echo "Opening the AiNxt OS Console (--run)…"
  exec "$CONSOLE" --config "$CONFIG"
fi
