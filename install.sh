#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
PROJECT_ROOT="$(cd -- "$(dirname -- "$SCRIPT_PATH")" && pwd)"
BIN_DIR="$HOME/.local/bin"
DEST="$BIN_DIR/adin"
SOURCE="$PROJECT_ROOT/bin/adin"

# Check first so a pre-existing unrelated command does not leave a partial install.
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

# Install user-local manual and shell completion definitions.
MAN_DIR="$HOME/.local/share/man/man1"
BASH_COMPLETION_DIR="$HOME/.local/share/bash-completion/completions"
ZSH_COMPLETION_DIR="$HOME/.local/share/zsh/site-functions"
FISH_COMPLETION_DIR="$HOME/.config/fish/completions"

install -D -m 0644 "$PROJECT_ROOT/man/adin.1" "$MAN_DIR/adin.1"
install -D -m 0644 "$PROJECT_ROOT/completions/bash/adin" "$BASH_COMPLETION_DIR/adin"
install -D -m 0644 "$PROJECT_ROOT/completions/zsh/_adin" "$ZSH_COMPLETION_DIR/_adin"
install -D -m 0644 "$PROJECT_ROOT/completions/fish/adin.fish" "$FISH_COMPLETION_DIR/adin.fish"

# Bash: source the user completion explicitly so it also works without the
# bash-completion package. Keep this block idempotent.
BASHRC="$HOME/.bashrc"
mkdir -p "$HOME"
touch "$BASHRC"
if ! grep -Fq '# >>> ADIN shell integration >>>' "$BASHRC"; then
    cat >> "$BASHRC" <<'BASH_BLOCK'

# >>> ADIN shell integration >>>
if [[ -r "$HOME/.local/share/bash-completion/completions/adin" ]]; then
    source "$HOME/.local/share/bash-completion/completions/adin"
fi
export MANPATH="$HOME/.local/share/man${MANPATH:+:$MANPATH}:"
# <<< ADIN shell integration <<<
BASH_BLOCK
fi

# Zsh: fpath must be set before compinit. Prepend a small block atomically,
# and only add compinit when the user's existing config doesn't mention it.
ZSHRC="$HOME/.zshrc"
if ! grep -Fq '# >>> ADIN shell integration >>>' "$ZSHRC" 2>/dev/null; then
    mkdir -p "$HOME"
    TEMP_ZSHRC="$(mktemp "$HOME/.zshrc.adin.XXXXXX")"
    if [[ -f "$ZSHRC" ]] && grep -Eq 'compinit' "$ZSHRC"; then
        cat > "$TEMP_ZSHRC" <<'ZSH_BLOCK'
# >>> ADIN shell integration >>>
fpath=("$HOME/.local/share/zsh/site-functions" $fpath)
export MANPATH="$HOME/.local/share/man${MANPATH:+:$MANPATH}:"
# <<< ADIN shell integration <<<

ZSH_BLOCK
    else
        cat > "$TEMP_ZSHRC" <<'ZSH_BLOCK'
# >>> ADIN shell integration >>>
fpath=("$HOME/.local/share/zsh/site-functions" $fpath)
export MANPATH="$HOME/.local/share/man${MANPATH:+:$MANPATH}:"
autoload -Uz compinit && compinit
# <<< ADIN shell integration <<<

ZSH_BLOCK
    fi
    if [[ -f "$ZSHRC" ]]; then
        cat "$ZSHRC" >> "$TEMP_ZSHRC"
        chmod --reference="$ZSHRC" "$TEMP_ZSHRC" 2>/dev/null || true
    fi
    mv "$TEMP_ZSHRC" "$ZSHRC"
fi

printf 'ADIN launcher installed at: %s\n' "$DEST"
printf 'Manual page installed at: %s\n' "$MAN_DIR/adin.1"
printf 'Shell completions installed for Bash, Zsh, and Fish.\n'
printf 'Restart your terminal, or reload your shell configuration.\n'
printf 'Usage: adin --help | man adin\n'
printf 'If man cannot find the page, run: man -M "$HOME/.local/share/man" adin\n'
printf 'This installation does not download packages or configure network access.\n'
