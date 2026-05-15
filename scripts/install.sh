#!/usr/bin/env bash
# adoqr installer for Linux / macOS / WSL
# -------------------------------------------------------------
# One-liner:
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/microsoft/adoqr/main/scripts/install.sh)"
#
# Env vars (optional):
#   ADOQR_REF       Git ref / tag to install from (default: main)
#   ADOQR_INSTALL_DIR   Install directory (default: $HOME/.adoqr)
#   ADOQR_NO_PATH   Set to 1 to skip PATH update
# -------------------------------------------------------------
set -euo pipefail

REF="${ADOQR_REF:-main}"
INSTALL_DIR="${ADOQR_INSTALL_DIR:-$HOME/.adoqr}"
RAW_BASE="https://raw.githubusercontent.com/microsoft/adoqr/${REF}"
SCRIPT_NAME="invoke-adoqr.ps1"
SCHEMA_PATH="schemas/scan.schema.json"

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
info()  { printf '  %s\n' "$*"; }
warn()  { printf '\033[33m  %s\033[0m\n' "$*"; }
fail()  { printf '\033[31m  %s\033[0m\n' "$*" >&2; exit 1; }

bold "adoqr installer"
info "Ref         : $REF"
info "Install dir : $INSTALL_DIR"

# --- Prerequisites ------------------------------------------------------------
command -v curl >/dev/null 2>&1 || fail "curl is required but was not found"

if command -v pwsh >/dev/null 2>&1; then
    PWSH_VER="$(pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>/dev/null || echo 'unknown')"
    info "PowerShell  : $PWSH_VER"
else
    warn "PowerShell 7+ (pwsh) was not found on PATH."
    warn "Install it from https://learn.microsoft.com/powershell/scripting/install/installing-powershell"
fi

if command -v az >/dev/null 2>&1; then
    AZ_VER="$(az version --query '\"azure-cli\"' -o tsv 2>/dev/null || echo 'unknown')"
    info "Azure CLI   : $AZ_VER"
else
    warn "Azure CLI (az) was not found on PATH."
    warn "Install it from https://learn.microsoft.com/cli/azure/install-azure-cli"
fi

# --- Download -----------------------------------------------------------------
mkdir -p "$INSTALL_DIR/schemas"
info "Downloading $SCRIPT_NAME..."
curl -fsSL "$RAW_BASE/$SCRIPT_NAME" -o "$INSTALL_DIR/$SCRIPT_NAME"
chmod +x "$INSTALL_DIR/$SCRIPT_NAME" || true

info "Downloading remediation-steps.psd1..."
curl -fsSL "$RAW_BASE/remediation-steps.psd1" -o "$INSTALL_DIR/remediation-steps.psd1" || warn "remediation-steps.psd1 not found at $REF (older release?); continuing."

info "Downloading $SCHEMA_PATH..."
curl -fsSL "$RAW_BASE/$SCHEMA_PATH" -o "$INSTALL_DIR/$SCHEMA_PATH" || warn "scan.schema.json not found at $REF (older release?); continuing."

# --- adoqr launcher shim ------------------------------------------------------
LAUNCHER="$INSTALL_DIR/adoqr"
cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
# adoqr launcher — invokes the bundled invoke-adoqr.ps1
exec pwsh -NoProfile -File "$INSTALL_DIR/$SCRIPT_NAME" "\$@"
EOF
chmod +x "$LAUNCHER"

bold "Installed."
info "Script    : $INSTALL_DIR/$SCRIPT_NAME"
info "Launcher  : $LAUNCHER"

# --- PATH wiring --------------------------------------------------------------
if [[ "${ADOQR_NO_PATH:-0}" != "1" ]]; then
    case ":$PATH:" in
        *":$INSTALL_DIR:"*) info "PATH      : already includes $INSTALL_DIR" ;;
        *)
            SHELL_NAME="$(basename "${SHELL:-bash}")"
            case "$SHELL_NAME" in
                zsh)  RC="$HOME/.zshrc"  ;;
                bash) RC="$HOME/.bashrc" ;;
                fish) RC="$HOME/.config/fish/config.fish" ;;
                *)    RC="$HOME/.profile" ;;
            esac
            if [[ -f "$RC" ]] && grep -q "adoqr" "$RC" 2>/dev/null; then
                info "PATH      : entry already present in $RC"
            else
                if [[ "$SHELL_NAME" == "fish" ]]; then
                    echo "set -gx PATH $INSTALL_DIR \$PATH  # adoqr" >> "$RC"
                else
                    echo "export PATH=\"$INSTALL_DIR:\$PATH\"  # adoqr" >> "$RC"
                fi
                info "PATH      : added $INSTALL_DIR to $RC (open a new shell to activate)"
            fi
        ;;
    esac
fi

bold "Run:"
info "  adoqr -Organization MyOrg"
info "  adoqr -Organization MyOrg -OutputFormat all"
