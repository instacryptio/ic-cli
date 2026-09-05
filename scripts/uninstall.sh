#!/usr/bin/env bash
#
# Instacrypt CLI (icc) uninstaller.
#
#   curl -sL https://instacrypt.io/ic-cli/uninstall.sh | bash
#
# Removes the icc binary from the common install locations and (optionally)
# strips the PATH entry the installer added to your shell profile.
#
set -e

BINARY="icc"
MARKER="# Added by icc installer"

# --- colors / decoration ---------------------------------------------------
if [ -t 1 ]; then
  BRAND=$'\033[38;2;170;199;56m'
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  RED=$'\033[31m'
  RESET=$'\033[0m'
else
  BRAND='' BOLD='' DIM='' RED='' RESET=''
fi

say()  { printf '%s\n' "$*"; }
info() { printf '%s\n' "${DIM}$*${RESET}"; }
err()  { printf '%s\n' "${RED}$*${RESET}" >&2; }

banner() {
  printf '%s' "${BRAND}"
  cat <<'ART'

░▒▓█▓▒░░▒▓██████▓▒░        ░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░░▒▓██████▓▒░        ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░
ART
  printf '%s' "${RESET}"
  printf '%s\n\n' "  ${BOLD}Uninstaller${RESET}"
}

# Reads the controlling terminal even under `curl | bash`; falls back to the
# provided default when there is no tty.
ask() {
  local prompt="$1" default="$2" reply=""
  if { true > /dev/tty; } 2>/dev/null; then
    printf '%s' "$prompt" > /dev/tty
    IFS= read -r reply < /dev/tty 2>/dev/null || reply=""
  fi
  [ -n "$reply" ] && printf '%s' "$reply" || printf '%s' "$default"
}

banner

# --- 1. locate installed binaries -----------------------------------------
info "🔍 Looking for icc..."
CANDIDATES="${HOME}/.local/bin/${BINARY} /usr/local/bin/${BINARY} /usr/bin/${BINARY}"

# Include anything else on PATH named icc (dedup against the candidate list).
if command -v "$BINARY" >/dev/null 2>&1; then
  ON_PATH="$(command -v "$BINARY")"
  case " $CANDIDATES " in
    *" $ON_PATH "*) : ;;
    *) CANDIDATES="$CANDIDATES $ON_PATH" ;;
  esac
fi

FOUND=""
for p in $CANDIDATES; do
  [ -e "$p" ] && FOUND="$FOUND $p"
done
FOUND="${FOUND# }"

if [ -z "$FOUND" ]; then
  say "   No icc binary found in the usual locations."
else
  say "   Found:"
  for p in $FOUND; do say "     • $p"; done
  say ""
  ANS="$(ask "Remove ${BOLD}icc${RESET}? [Y/n]: " "Y")"
  case "$ANS" in
    n|N|no|No) say "Canceled."; exit 0 ;;
  esac
  for p in $FOUND; do
    if [ -w "$(dirname "$p")" ]; then
      rm -f "$p"
    elif command -v sudo >/dev/null 2>&1; then
      info "   (elevated permissions required to remove $p)"
      sudo rm -f "$p"
    else
      err "   No write access to remove $p and 'sudo' is unavailable — skipped."
      continue
    fi
    say "   🗑  Removed $p"
  done
fi
say ""

# --- 2. offer to strip the PATH entry the installer added ------------------
PROFILES="${HOME}/.bashrc ${HOME}/.bash_profile ${HOME}/.zshrc ${HOME}/.profile ${HOME}/.config/fish/config.fish"
DIRTY=""
for f in $PROFILES; do
  [ -f "$f" ] && grep -qF "$MARKER" "$f" 2>/dev/null && DIRTY="$DIRTY $f"
done
DIRTY="${DIRTY# }"

if [ -n "$DIRTY" ]; then
  say "The installer added a PATH entry to:"
  for f in $DIRTY; do say "     • $f"; done
  ANS="$(ask "Remove those entries too? [y/N]: " "N")"
  case "$ANS" in
    y|Y|yes|Yes)
      for f in $DIRTY; do
        # Drop each marker comment line AND the line immediately after it.
        tmp="$(mktemp "${TMPDIR:-/tmp}/icc-prof.XXXXXX")"
        awk -v m="$MARKER" '
          skip { skip=0; next }
          index($0, m) { skip=1; next }
          { print }
        ' "$f" > "$tmp" && cat "$tmp" > "$f"
        rm -f "$tmp"
        say "   🔗 Cleaned $f"
      done
      ;;
    *)
      info "   Left shell profiles untouched."
      ;;
  esac
  say ""
fi

# --- 3. done ---------------------------------------------------------------
printf '%s\n' "${BRAND}${BOLD}** Uninstall Completed **${RESET}"
say ""
