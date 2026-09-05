#!/usr/bin/env bash
#
# Instacrypt CLI (icc) installer.
#
#   curl -sL https://instacrypt.io/ic-cli/install.sh | bash
#
# Downloads the latest icc release binary for your OS + CPU architecture and
# installs it either per-user (~/.local/bin) or system-wide (/usr/local/bin).
#
set -e

REPO="instacryptio/ic-cli"
BINARY="icc"
ISSUES_URL="https://github.com/${REPO}/issues"
LATEST_BASE="https://github.com/${REPO}/releases/latest/download"

# --- colors / decoration ---------------------------------------------------
# Brand green (#aac738) via truecolor ANSI; degrade gracefully when the output
# isn't a terminal (piped/redirected).
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
  printf '%s\n\n' "  ${BOLD}Installer${RESET}${DIM} — post-quantum ready, password-less file encryption${RESET}"
}

# --- prompt helper (reads the terminal even under `curl | bash`) ------------
# stdin is the curl pipe, so interactive reads must come from /dev/tty. When
# there's no tty (fully non-interactive), the caller's default is used.
ask() {
  # $1 = prompt, $2 = default answer when non-interactive
  local prompt="$1" default="$2" reply=""
  # Probe whether a controlling terminal can actually be opened (not just that
  # a /dev/tty node exists) so headless runs fall back silently to the default.
  if { true > /dev/tty; } 2>/dev/null; then
    printf '%s' "$prompt" > /dev/tty
    IFS= read -r reply < /dev/tty 2>/dev/null || reply=""
  fi
  [ -n "$reply" ] && printf '%s' "$reply" || printf '%s' "$default"
}

banner

# --- 1. detect OS ----------------------------------------------------------
info "🔍 Detecting your platform..."
UNAME_S="$(uname -s)"
case "$UNAME_S" in
  Linux)   OS="linux" ;;
  Darwin)  OS="macos" ;;
  FreeBSD) OS="freebsd" ;;
  OpenBSD) OS="openbsd" ;;
  *)
    err "This operating system is not currently supported. Submit an issue at ${ISSUES_URL} to report this if you think this is an error."
    exit 1
    ;;
esac

# --- 2. detect CPU architecture -------------------------------------------
UNAME_M="$(uname -m)"
case "$UNAME_M" in
  x86_64|amd64)        ARCH="amd64" ;;
  aarch64|arm64)       ARCH="arm64" ;;
  *)
    err "CPU architecture '${UNAME_M}' is not currently supported. Submit an issue at ${ISSUES_URL} to report this if you think this is an error."
    exit 1
    ;;
esac

ASSET="${BINARY}-${OS}-${ARCH}"
say "   Platform: ${BOLD}${OS}/${ARCH}${RESET}"
say ""

# --- 3. choose install scope ----------------------------------------------
say "How would you like to install ${BOLD}icc${RESET}?"
say "  ${BOLD}1${RESET}) Per-user     (~/.local/bin — no admin required)"
say "  ${BOLD}2${RESET}) System-wide  (/usr/local/bin — may prompt for sudo)"
CHOICE="$(ask "Choose [1/2] (default 1): " "1")"
say ""

TARGET_DIR=""
USE_SUDO=""
ADDED_PATH_TO=""

case "$CHOICE" in
  2)
    # Pick the best system-wide bin dir for this OS.
    if [ -d /usr/local/bin ]; then
      TARGET_DIR="/usr/local/bin"
    else
      TARGET_DIR="/usr/bin"
    fi
    info "📁 Installing system-wide to ${TARGET_DIR}"
    if [ ! -w "$TARGET_DIR" ]; then
      if command -v sudo >/dev/null 2>&1; then
        USE_SUDO="sudo"
        info "   (elevated permissions required — you may be prompted for your password)"
      else
        err "No write access to ${TARGET_DIR} and 'sudo' is not available. Re-run as root, or choose per-user install."
        exit 1
      fi
    fi
    ;;
  *)
    TARGET_DIR="${HOME}/.local/bin"
    info "📁 Installing per-user to ${TARGET_DIR}"
    if [ ! -d "$TARGET_DIR" ]; then
      mkdir -p "$TARGET_DIR"
      say "   Created ${TARGET_DIR}"
    fi
    # Ensure it's on PATH; append to the right shell profile if missing.
    case ":${PATH}:" in
      *":${TARGET_DIR}:"*) : ;;   # already on PATH
      *)
        info "🔗 ${TARGET_DIR} is not on your PATH — adding it..."
        shell_name="$(basename "${SHELL:-}")"
        case "$shell_name" in
          zsh)  profile="${HOME}/.zshrc" ;;
          bash) if [ "$OS" = "macos" ]; then profile="${HOME}/.bash_profile"; else profile="${HOME}/.bashrc"; fi ;;
          fish) profile="${HOME}/.config/fish/config.fish" ;;
          *)    profile="${HOME}/.profile" ;;
        esac
        mkdir -p "$(dirname "$profile")"
        if [ "$shell_name" = "fish" ]; then
          printf '\n# Added by icc installer\nfish_add_path "%s"\n' "$TARGET_DIR" >> "$profile"
        else
          printf '\n# Added by icc installer\nexport PATH="%s:$PATH"\n' "$TARGET_DIR" >> "$profile"
        fi
        ADDED_PATH_TO="$profile"
        say "   Added a PATH entry to ${profile}"
        ;;
    esac
    ;;
esac
say ""

# --- 4. download the binary -----------------------------------------------
URL="${LATEST_BASE}/${ASSET}"
info "⬇️  Downloading ${ASSET}..."
say "   ${DIM}${URL}${RESET}"
TMP="$(mktemp "${TMPDIR:-/tmp}/icc.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

if command -v curl >/dev/null 2>&1; then
  curl -fSL --progress-bar "$URL" -o "$TMP"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TMP" "$URL"
else
  err "Neither 'curl' nor 'wget' is available to download the binary."
  exit 1
fi

if [ ! -s "$TMP" ]; then
  err "Download failed or produced an empty file. Please try again, or report at ${ISSUES_URL}."
  exit 1
fi
chmod +x "$TMP"

# --- 5. install (rename to plain 'icc') -----------------------------------
DEST="${TARGET_DIR}/${BINARY}"
$USE_SUDO mv "$TMP" "$DEST"
trap - EXIT
say ""

# --- 6. done ---------------------------------------------------------------
printf '%s\n' "${BRAND}${BOLD}** Installation Completed **${RESET}"
say "   ${BOLD}icc${RESET} installed to ${DEST}"
if [ -n "$ADDED_PATH_TO" ]; then
  say "   PATH updated in ${ADDED_PATH_TO}"
fi
say ""
printf '%s\n' "⚠️  You may need to close and reopen your existing terminal windows for icc to work as expected..."
say ""
