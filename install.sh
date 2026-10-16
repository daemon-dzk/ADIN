#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
PROJECT_ROOT="$(cd -- "$(dirname -- "$SCRIPT_PATH")" && pwd)"
BIN_DIR="$HOME/.local/bin"
DEST="$BIN_DIR/adin"
SOURCE="$PROJECT_ROOT/bin/adin"

mkdir -p "$BIN_DIR"
if [[ -e "$DEST" || -L "$DEST" ]]; then
    EXISTING="$(readlink -f -- "$DEST" 2>/dev/null || true)"
    if [[ "$EXISTING" != "$SOURCE" ]]; then
        printf 'Refusing to overwrite existing path: %s\n' "$DEST" >&2
        printf 'Move it manually if you want to install ADIN at that location.\n' >&2
        exit 1
    fi
else
    ln -s "$SOURCE" "$DEST"
fi

printf 'ADIN launcher installed at: %s\n' "$DEST"
case ":$PATH:" in
  *":$BIN_DIR:"*) printf 'You can now run: adin --version\n' ;;
  *)
    printf 'Your PATH does not include %s. Add this line to your shell profile:\n' "$BIN_DIR"
    printf '  export PATH="$HOME/.local/bin:$PATH"\n'
    printf 'Then restart the shell (or source your profile).\n'
    ;;
esac
printf 'This installation does not download packages or configure network access.\n'
