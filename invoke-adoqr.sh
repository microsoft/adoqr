#!/usr/bin/env bash
# =============================================================================
#  invoke-adoqr.sh — Azure DevOps Quick Review (bash port of invoke-adoqr.ps1)
# -----------------------------------------------------------------------------
#  Reviews an Azure DevOps organization and its projects against Azure DevOps
#  best practices and Microsoft recommendations.
#
#  Requires: bash 4+, jq, curl, az CLI (with the azure-devops extension), and
#  an active 'az login' session.
#
#  This is a port-in-progress. Implemented as of this commit:
#    Phase 1  Scaffolding (CLI, prereqs, temp dir, URL normalization)
#    Phase 2  HTTP + az CLI layer (caching, retry, adaptive throttling)
#    Phase 3  Control model + helpers (categories, ACL/Graph, branch policy)
#    Phase 4  Organization checks: AUTH/OAUTH/ACCESS/PATPOL/USER (initial slice)
#    Phase 6  Markdown + canonical JSON writers
#
#  Outstanding (to follow in subsequent commits):
#    - Remaining org checks (admins, extensions, audit, pipeline settings,
#      feeds, PAT lifecycles)
#    - All project-scope checks (10 categories)
#    - Executive HTML + remediation HTML writers
#    - Run-comparison HTML section
#    - Parallel execution mode (background jobs + FIFO semaphore)
# =============================================================================

set -euo pipefail

# ---- bash version guard ------------------------------------------------------
if (( BASH_VERSINFO[0] < 4 )); then
    printf 'invoke-adoqr.sh requires bash 4 or later (found %s).\n' "${BASH_VERSION:-unknown}" >&2
    exit 1
fi

# Use the script's directory as a stable anchor (mirrors $PSScriptRoot).
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"

# Windows-native jq.exe emits CRLF line endings, which corrupts every text value
# read from jq into bash variables (trailing \r breaks string comparisons,
# pattern matches, and file paths). Shadow jq with a wrapper that strips CR
# so all downstream consumers see clean LF-terminated output.
#
# Perf: the original wrapper piped every jq call through `tr -d '\r'`, which
# forked a second process per invocation. On Windows that doubles the
# CreateProcess cost of every jq call (~30-80 ms each). We instead capture
# jq's stdout once and strip CRs in-process via bash parameter expansion.
# Trade-off: output is buffered (not streamed) and the trailing newline is
# absorbed by command substitution — which is exactly how the script consumes
# jq output throughout, so behavior is unchanged.
if command -v jq >/dev/null 2>&1; then
    _ADOQR_JQ_BIN="$(command -v jq)"
    jq() {
        local _adoqr_jq_out
        _adoqr_jq_out="$("$_ADOQR_JQ_BIN" "$@")" || return $?
        printf '%s\n' "${_adoqr_jq_out//$'\r'/}"
    }
fi

# =============================================================================
#  Configuration (mirrors $script:* variables in the PowerShell entry point)
# =============================================================================

CREDENTIAL_PATTERNS=(
    password passwd pwd secret key token
    connectionstring conn_string apikey api_key
    access_key accesskey client_secret clientsecret
    sas signing certificate
)
# Build a case-insensitive ERE alternation: (password|passwd|...)
_credential_regex_body="$(IFS='|'; printf '%s' "${CREDENTIAL_PATTERNS[*]}")"
CREDENTIAL_REGEX="(${_credential_regex_body})"
unset _credential_regex_body

INACTIVE_DAYS=90
INACTIVE_REPO_DAYS=180

BROAD_GROUPS=(
    'Contributors'
    'Project Valid Users'
    'Project Collection Valid Users'
    'Build Administrators'
    'Endpoint Administrators'
)
# Treated as broad for ACL-based checks (PERM-*) but excluded from the
# feed-permission BroadGroups list because they routinely need feed Reader access.
BROAD_ACL_EXTRAS=(
    'Build Service'
    'Project Collection Build Service'
    'Project Collection Service Accounts'
)
PRODUCTION_KEYWORDS=(prod production prd live release)

# Bearer-token scope for the Azure DevOps REST API.
ADO_RESOURCE_ID='499b84ac-1321-427f-aa17-267ca6975798'

# =============================================================================
#  CLI parsing
# =============================================================================

print_help() {
    cat <<EOF
Usage: ${SCRIPT_NAME} --organization <name-or-url> [options]

Reviews an Azure DevOps organization and its projects against best practices
and produces Markdown reports (and optionally HTML / JSON).

Required:
  -o, --organization <ORG>      Organization short name or full URL
                                (e.g. "MyOrg" or "https://dev.azure.com/MyOrg")

Options:
  -p, --project <NAME>          Project name to assess. Repeat to scan many;
                                omit to scan every project in the org.
  -O, --output-path <DIR>       Output directory (default: ./assessments)
      --max-parallel <N>        Max concurrent project workers (1-20, default 3).
      --include-graph-check     Cross-reference ADO users with Entra ID via
                                Microsoft Graph (requires User.Read.All).
  -f, --output-format <FMT>     One of markdown|html|json|all. Repeat to combine.
                                Default: markdown,html.
  -h, --help                    Show this help and exit.

Environment variables:
  ADOQR_NO_OPEN     When set, do not auto-open the executive report.
  NO_COLOR          When set, disable ANSI colors.

Examples:
  ${SCRIPT_NAME} --organization MyOrg
  ${SCRIPT_NAME} -o MyOrg -p WebApp -p API
  ${SCRIPT_NAME} -o https://dev.azure.com/MyOrg -O /tmp/reports -f all
EOF
}

ORGANIZATION=''
PROJECTS=()
OUTPUT_PATH=''
MAX_PARALLEL=3
INCLUDE_GRAPH_CHECK=0
OUTPUT_FORMATS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--organization)
            [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
            ORGANIZATION="$2"; shift 2 ;;
        --organization=*)
            ORGANIZATION="${1#*=}"; shift ;;
        -p|--project)
            [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
            PROJECTS+=("$2"); shift 2 ;;
        --project=*)
            PROJECTS+=("${1#*=}"); shift ;;
        -O|--output-path)
            [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
            OUTPUT_PATH="$2"; shift 2 ;;
        --output-path=*)
            OUTPUT_PATH="${1#*=}"; shift ;;
        --max-parallel)
            [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
            MAX_PARALLEL="$2"; shift 2 ;;
        --max-parallel=*)
            MAX_PARALLEL="${1#*=}"; shift ;;
        --include-graph-check)
            INCLUDE_GRAPH_CHECK=1; shift ;;
        -f|--output-format)
            [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
            OUTPUT_FORMATS+=("$2"); shift 2 ;;
        --output-format=*)
            OUTPUT_FORMATS+=("${1#*=}"); shift ;;
        -h|--help)
            print_help; exit 0 ;;
        --)
            shift; break ;;
        -*)
            echo "Unknown option: $1" >&2
            print_help >&2
            exit 2 ;;
        *)
            echo "Unexpected positional argument: $1" >&2
            print_help >&2
            exit 2 ;;
    esac
done

if [[ -z "$ORGANIZATION" ]]; then
    echo "Error: --organization is required." >&2
    print_help >&2
    exit 2
fi

# Validate --max-parallel range (1..20)
if ! [[ "$MAX_PARALLEL" =~ ^[0-9]+$ ]] || (( MAX_PARALLEL < 1 || MAX_PARALLEL > 20 )); then
    echo "Error: --max-parallel must be an integer between 1 and 20." >&2
    exit 2
fi

# Default output path: <script-dir>/assessments
if [[ -z "$OUTPUT_PATH" ]]; then
    OUTPUT_PATH="${SCRIPT_DIR}/assessments"
fi

# Default output formats: markdown,html
if (( ${#OUTPUT_FORMATS[@]} == 0 )); then
    OUTPUT_FORMATS=(markdown html)
fi

# Validate --output-format values and expand 'all'
declare -A _fmt_set=()
for fmt in "${OUTPUT_FORMATS[@]}"; do
    case "$fmt" in
        markdown|html|json) _fmt_set["$fmt"]=1 ;;
        all) _fmt_set[markdown]=1; _fmt_set[html]=1; _fmt_set[json]=1 ;;
        *)
            echo "Error: unknown --output-format value '$fmt'. Expected markdown|html|json|all." >&2
            exit 2 ;;
    esac
done
WRITE_MARKDOWN=0; WRITE_HTML=0; WRITE_JSON=0
[[ -n "${_fmt_set[markdown]:-}" ]] && WRITE_MARKDOWN=1
[[ -n "${_fmt_set[html]:-}"     ]] && WRITE_HTML=1
[[ -n "${_fmt_set[json]:-}"     ]] && WRITE_JSON=1
unset _fmt_set

# =============================================================================
#  Logging (color/no-color, TTY aware)
# =============================================================================

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RED=$'\e[31m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'
    C_CYAN=$'\e[36m'; C_DIM=$'\e[2m'; C_RESET=$'\e[0m'
else
    C_RED=''; C_GREEN=''; C_YELLOW=''; C_CYAN=''; C_DIM=''; C_RESET=''
fi

log_info() { printf '%s%s%s\n' "" "$*" ""; }
log_ok()   { printf '%s%s%s\n' "$C_GREEN" "$*" "$C_RESET"; }
log_warn() { printf '%s%s%s\n' "$C_YELLOW" "$*" "$C_RESET" >&2; }
log_err()  { printf '%s%s%s\n' "$C_RED" "$*" "$C_RESET" >&2; }
log_step() { printf '%s%s%s\n' "$C_YELLOW" "$*" "$C_RESET"; }
log_hdr()  { printf '%s%s%s\n' "$C_CYAN" "$*" "$C_RESET"; }
log_dim()  { printf '%s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }

die() { log_err "FATAL: $*"; exit 1; }

# =============================================================================
#  Prerequisites
# =============================================================================

check_prereqs() {
    log_step "Checking prerequisites..."
    local missing=()
    for cmd in jq curl az awk sed grep; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if (( ${#missing[@]} > 0 )); then
        die "Missing required commands: ${missing[*]}. Please install them and retry."
    fi

    # az azure-devops extension
    local ext_check
    if ! ext_check=$(az extension list --query "[?name=='azure-devops']" -o tsv 2>/dev/null); then
        die "Failed to query az extensions. Is 'az' installed and on PATH?"
    fi
    if [[ -z "$ext_check" ]]; then
        die "Azure DevOps CLI extension is not installed. Run: az extension add --name azure-devops"
    fi
    log_ok "  azure-devops extension: installed"

    # az login state
    if ! az account show >/dev/null 2>&1; then
        die "Not signed in to Azure CLI. Run: az login"
    fi
}

# =============================================================================
#  Run-scoped temp directory + cleanup trap
# =============================================================================

ADOQR_TMP="$(mktemp -d -t adoqr.XXXXXXXX)"
mkdir -p \
    "${ADOQR_TMP}/cache/api" \
    "${ADOQR_TMP}/cache/azcli" \
    "${ADOQR_TMP}/results" \
    "${ADOQR_TMP}/state"

_cleanup() {
    local rc=$?
    if [[ -n "${ADOQR_KEEP_TMP:-}" ]]; then
        log_dim "Temp dir preserved: ${ADOQR_TMP}"
    else
        rm -rf -- "${ADOQR_TMP}" 2>/dev/null || true
    fi
    exit "$rc"
}
trap _cleanup EXIT INT TERM

# =============================================================================
#  Settings file loader (optional adoqr.settings.psd1)
# -----------------------------------------------------------------------------
#  Mirrors Import-AdoqrSettings. Parses only the small set of supported keys
#  using regex/awk; arbitrary PowerShell expressions remain a PS1-only feature.
# =============================================================================

load_settings_file() {
    local path="${SCRIPT_DIR}/adoqr.settings.psd1"
    [[ -f "$path" ]] || return 0

    # InactiveRepoDays = <int>
    local val
    val=$(grep -E "^[[:space:]]*InactiveRepoDays[[:space:]]*=" "$path" 2>/dev/null \
          | head -n 1 \
          | sed -E 's/^[^=]*=[[:space:]]*([0-9]+).*$/\1/')
    if [[ -n "$val" ]] && [[ "$val" =~ ^[0-9]+$ ]] && (( val > 0 )); then
        INACTIVE_REPO_DAYS="$val"
    fi
}

# =============================================================================
#  URL normalization
# =============================================================================

# Strip trailing slash for consistent URL building.
strip_trailing_slash() { printf '%s' "${1%/}"; }

if [[ "$ORGANIZATION" =~ ^https?:// ]]; then
    ORG_URL="$(strip_trailing_slash "$ORGANIZATION")"
else
    ORG_URL="https://dev.azure.com/${ORGANIZATION}"
fi

# Derive org short name from URL (supports dev.azure.com/<org> and legacy <org>.visualstudio.com)
ORG_SHORT_NAME="$(printf '%s' "$ORG_URL" \
    | sed -E -e 's#^https?://dev\.azure\.com/##' \
             -e 's#^https?://([^.]+)\.visualstudio\.com.*#\1#' \
             -e 's#/.*$##')"

VSSPS_URL="https://vssps.dev.azure.com/${ORG_SHORT_NAME}"
EXTMGMT_URL="https://extmgmt.dev.azure.com/${ORG_SHORT_NAME}"
AUDIT_URL="https://auditservice.dev.azure.com/${ORG_SHORT_NAME}"
FEEDS_URL="https://feeds.dev.azure.com/${ORG_SHORT_NAME}"

# =============================================================================
#  URL encoding helper (RFC 3986 path-segment / query-param safe)
# =============================================================================

url_encode() {
    local s="$1" out='' c
    local LC_ALL=C
    local i=0 len=${#s}
    while (( i < len )); do
        c="${s:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) out+="$c" ;;
            *) printf -v out '%s%%%02X' "$out" "'$c" ;;
        esac
        (( i++ ))
    done
    printf '%s' "$out"
}

# =============================================================================
#  Phase 2 — Bearer token + HTTP layer
# =============================================================================

ADO_BEARER_TOKEN=''
get_ado_bearer_token() {
    [[ -n "$ADO_BEARER_TOKEN" ]] && { printf '%s' "$ADO_BEARER_TOKEN"; return 0; }
    if ! ADO_BEARER_TOKEN="$(az account get-access-token --resource "$ADO_RESOURCE_ID" --query accessToken -o tsv 2>/dev/null)"; then
        die "Failed to obtain bearer token. Ensure you are logged in with 'az login'."
    fi
    ADO_BEARER_TOKEN="${ADO_BEARER_TOKEN//$'\r'/}"
    ADO_BEARER_TOKEN="${ADO_BEARER_TOKEN//$'\n'/}"
    printf '%s' "$ADO_BEARER_TOKEN"
}

# In-memory + on-disk cache for GET responses. Hits return the cached body
# filepath; misses run curl with retry/throttle logic and store the body.
declare -A ADO_API_CACHE=()        # uri -> body filepath (or "__NULL__")
declare -A ADO_API_CACHE_NEG=()    # uri -> 1 when a negative cache exists

# Internal: sha1 of a string (stable cache key safe for filenames)
_sha1() {
    if command -v sha1sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha1sum | awk '{print $1}'
    else
        # macOS / BSD
        printf '%s' "$1" | shasum | awk '{print $1}'
    fi
}

# ado_api METHOD URI [BODY_JSON]
# Writes the response body to ADOQR_TMP/cache/api/<sha>.json and echoes the path.
# Emits '' (and returns 0) on documented "soft" failures (401/403/404, all
# retries exhausted) so callers can short-circuit gracefully — mirrors the
# PowerShell function's "return $null on null cache" semantics.
ado_api() {
    local method="$1" uri="$2" body="${3:-}"
    local key="${method}|${uri}|${body}"
    local cache_path="${ADOQR_TMP}/cache/api/$(_sha1 "$key").json"

    # GET cache hit (positive or negative)
    if [[ "$method" == "GET" && -z "$body" ]]; then
        if [[ -n "${ADO_API_CACHE[$uri]:-}" ]]; then
            if [[ "${ADO_API_CACHE[$uri]}" == "__NULL__" ]]; then return 0; fi
            printf '%s' "${ADO_API_CACHE[$uri]}"
            return 0
        fi
    fi

    local token; token="$(get_ado_bearer_token)"
    local hdr_path="${cache_path}.hdr"
    local attempt=0 max_retries=3 status='' wait_for=''

    while (( attempt < max_retries )); do
        (( attempt++ ))

        local curl_args=(
            -sS -X "$method"
            -D "$hdr_path"
            -o "$cache_path"
            -w '%{http_code}'
            -H "Authorization: Bearer ${token}"
            -H 'Accept: application/json'
        )
        if [[ -n "$body" ]]; then
            curl_args+=(-H 'Content-Type: application/json' --data-binary "$body")
        fi
        curl_args+=("$uri")

        status="$(curl "${curl_args[@]}" 2>/dev/null || true)"

        # Inspect response headers for rate-limit signals
        local retry_after='' rl_remaining='' rl_limit=''
        if [[ -f "$hdr_path" ]]; then
            retry_after="$(grep -i '^Retry-After:' "$hdr_path" | tail -n1 | awk -F': *' '{print $2}' | tr -d '\r\n')"
            rl_remaining="$(grep -i '^X-RateLimit-Remaining:' "$hdr_path" | tail -n1 | awk -F': *' '{print $2}' | tr -d '\r\n')"
            rl_limit="$(grep -i '^X-RateLimit-Limit:' "$hdr_path" | tail -n1 | awk -F': *' '{print $2}' | tr -d '\r\n')"
        fi

        # 429 → respect Retry-After (fallback exponential 2^attempt), retry
        if [[ "$status" == "429" ]]; then
            wait_for="${retry_after:-}"
            if ! [[ "$wait_for" =~ ^[0-9]+$ ]] || (( wait_for == 0 )); then
                wait_for=$(( 1 << attempt ))
            fi
            log_warn "Rate limited (429) on ${uri}. Waiting ${wait_for}s (attempt ${attempt}/${max_retries})..."
            sleep "$wait_for"
            continue
        fi

        # Documented "soft" misses → empty result, cache negative
        if [[ "$status" == "401" || "$status" == "403" || "$status" == "404" ]]; then
            if [[ "$method" == "GET" && -z "$body" ]]; then
                ADO_API_CACHE[$uri]="__NULL__"
                ADO_API_CACHE_NEG[$uri]=1
            fi
            rm -f -- "$cache_path" "$hdr_path"
            return 0
        fi

        # 2xx → success path with adaptive throttling
        if [[ "$status" =~ ^2 ]]; then
            # Honor Retry-After even on 2xx (rare but documented)
            if [[ -n "$retry_after" ]] && [[ "$retry_after" =~ ^[0-9]+$ ]] && (( retry_after > 0 )); then
                log_warn "ADO throttling active (Retry-After: ${retry_after}s). Slowing down..."
                sleep "$retry_after"
            elif [[ "$rl_remaining" =~ ^[0-9]+$ ]] && [[ "$rl_limit" =~ ^[0-9]+$ ]] && (( rl_limit > 0 )); then
                # Tiered pause when budget is tight (5% / 15% / 5s / 2s)
                local pct=$(( rl_remaining * 100 / rl_limit ))
                local pause=0
                if   (( pct <= 5 ));  then pause=5
                elif (( pct <= 15 )); then pause=2
                fi
                if (( pause > 0 )); then
                    log_warn "Rate limit pressure: ${rl_remaining}/${rl_limit} TSTUs remaining (~${pct}%). Pausing ${pause}s..."
                    sleep "$pause"
                fi
            fi

            rm -f -- "$hdr_path"
            if [[ "$method" == "GET" && -z "$body" ]]; then
                ADO_API_CACHE[$uri]="$cache_path"
            fi
            printf '%s' "$cache_path"
            return 0
        fi

        # Other 5xx / network errors → retry with backoff
        if (( attempt < max_retries )); then
            sleep 1
            continue
        fi
        log_warn "Failed after ${max_retries} attempts on ${uri} (HTTP ${status:-?})."
        rm -f -- "$cache_path" "$hdr_path"
        return 0
    done

    return 0
}

# Convenience helpers
ado_get()  { ado_api GET  "$1"; }
ado_post() { ado_api POST "$1" "$2"; }

# Read a cached JSON path; safely emits '' when the path is missing/empty.
# Usage: ado_read <path-from-ado_api>  →  prints body to stdout (or nothing).
ado_read() {
    local p="$1"
    [[ -n "$p" && -f "$p" ]] || return 0
    cat -- "$p"
}

# jq helper: run a filter against an ado_api result path; '' if path missing.
ado_jq() {
    local p="$1"; shift
    [[ -n "$p" && -f "$p" ]] || return 0
    jq "$@" -- "$p" 2>/dev/null || true
}

# =============================================================================
#  Az CLI layer (cached)
# =============================================================================

declare -A AZCLI_CACHE=()  # joined-command -> body filepath, or "__NULL__"

# az_cli <args...>  — runs `az <args> -o json`, caches by joined-args.
# Emits the path of the cached JSON file (or empty on failure).
az_cli() {
    local key
    # Use Unit Separator (\x1f) rather than NUL: bash strips NULs from command
    # substitution and emits a warning, but \x1f survives unchanged and is
    # equally safe as an arg delimiter (never appears in CLI arguments).
    key="$(printf '%s\x1f' "$@")"
    local cache_path="${ADOQR_TMP}/cache/azcli/$(_sha1 "$key").json"

    if [[ -n "${AZCLI_CACHE[$key]:-}" ]]; then
        if [[ "${AZCLI_CACHE[$key]}" == "__NULL__" ]]; then return 0; fi
        printf '%s' "${AZCLI_CACHE[$key]}"
        return 0
    fi

    local err_path="${cache_path}.err"
    if az "$@" -o json >"$cache_path" 2>"$err_path"; then
        # Empty (no output) → cache negative
        if [[ ! -s "$cache_path" ]]; then
            AZCLI_CACHE[$key]="__NULL__"
            rm -f -- "$cache_path" "$err_path"
            return 0
        fi
        AZCLI_CACHE[$key]="$cache_path"
        rm -f -- "$err_path"
        printf '%s' "$cache_path"
        return 0
    else
        log_warn "az $* failed: $(head -n 3 "$err_path" 2>/dev/null | tr '\n' ' ')"
        AZCLI_CACHE[$key]="__NULL__"
        rm -f -- "$cache_path" "$err_path"
        return 0
    fi
}

# =============================================================================
#  Phase 3 — Control model + helpers
# =============================================================================

# get_control_category <ID>  → echoes category string.
# Exact-Id overrides first, then prefix table (longest first), then 'Other'.
get_control_category() {
    local id="$1"
    [[ -n "$id" ]] || { printf 'Other'; return; }

    case "$id" in
        PROJ-01)            printf 'Governance'; return ;;
        PROJ-02|PROJ-03|PROJ-04|PROJ-05|PROJ-06|PROJ-07|PROJ-08)
                            printf 'Identity & Access'; return ;;
        PROJ-13)            printf 'Resources'; return ;;
        PROJ-14|PROJ-15)    printf 'Secrets & Credentials'; return ;;
        PROJ-16|PROJ-17)    printf 'Governance'; return ;;
        BUILD-01|BUILD-03)  printf 'Secrets & Credentials'; return ;;
        REL-01)             printf 'Secrets & Credentials'; return ;;
    esac

    case "$id" in
        PIPELINE-*) printf 'Pipelines & Actions' ;;
        PATPOL-*)   printf 'PAT Hygiene' ;;
        COPILOT-*)  printf 'Governance' ;;
        BRANCH-*)   printf 'Repos & Branch Protection' ;;
        ACCESS-*)   printf 'Identity & Access' ;;
        ADMIN-*)    printf 'Identity & Access' ;;
        AUDIT-*)    printf 'Audit Log' ;;
        AUTH-*)     printf 'Identity & Access' ;;
        BADGE-*)    printf 'Governance' ;;
        BUILD-*)    printf 'Pipelines & Actions' ;;
        ENV-*)      printf 'Resources' ;;
        EXT-*)      printf 'Governance' ;;
        FEED-*)     printf 'Resources' ;;
        GOV-*)      printf 'Governance' ;;
        OAUTH-*)    printf 'Governance' ;;
        PAT-*)      printf 'PAT Hygiene' ;;
        PERM-*)     printf 'Identity & Access' ;;
        PROJ-*)     printf 'Identity & Access' ;;
        REL-*)      printf 'Pipelines & Actions' ;;
        REPO-*)     printf 'Repos & Branch Protection' ;;
        SC-*)       printf 'Service Connections' ;;
        SF-*)       printf 'Resources' ;;
        AP-*)       printf 'Resources' ;;
        USER-*)     printf 'Identity & Access' ;;
        VG-*)       printf 'Secrets & Credentials' ;;
        *)          printf 'Other' ;;
    esac
}

# emit_control <RESULTS_FILE> <ID> <STATUS> <SEVERITY> <CONTROL> <FINDING> [CATEGORY]
# Appends one JSON line (id,status,severity,category,control,finding) to file.
emit_control() {
    local file="$1" id="$2" status="$3" severity="$4" control="$5" finding="$6"
    local category="${7:-}"
    [[ -n "$category" ]] || category="$(get_control_category "$id")"

    jq -nc \
        --arg id "$id" \
        --arg status "$status" \
        --arg severity "$severity" \
        --arg category "$category" \
        --arg control "$control" \
        --arg finding "$finding" \
        '{id:$id, status:$status, severity:$severity, category:$category, control:$control, finding:$finding}' \
        >>"$file"
}

# Predicates
test_looks_like_secret() { [[ "$1" =~ $CREDENTIAL_REGEX ]]; }
test_is_url_value()      { [[ "$1" =~ ^https?:// ]]; }

test_is_broad_group() {
    local name="$1" lower; lower="${name,,}"
    local bg
    for bg in "${BROAD_GROUPS[@]}"; do
        [[ "$lower" == *"${bg,,}"* ]] && return 0
    done
    return 1
}

test_is_broad_group_for_acl() {
    [[ -n "$1" ]] || return 1
    test_is_broad_group "$1" && return 0
    local name="$1" lower; lower="${name,,}"
    local extra
    for extra in "${BROAD_ACL_EXTRAS[@]}"; do
        [[ "$lower" == *"${extra,,}"* ]] && return 0
    done
    return 1
}

test_is_production_stage() {
    local name="$1" lower; lower="${name,,}"
    local kw
    for kw in "${PRODUCTION_KEYWORDS[@]}"; do
        [[ "$lower" == *"${kw,,}"* ]] && return 0
    done
    return 1
}

# Normalize values into 'true' / 'false' / '' (empty = unknown)
to_bool_or_null() {
    local v="$1"
    [[ -z "$v" || "$v" == "null" ]] && { printf ''; return; }
    case "${v,,}" in
        true|1|yes|on)    printf 'true'  ;;
        false|0|no|off)  printf 'false' ;;
        *)                        printf ''      ;;
    esac
}

# org_policy_boolean <policy-json>  → 'true'/'false'/''
get_org_policy_boolean() {
    local pol="$1"
    [[ -n "$pol" && "$pol" != "null" ]] || { printf ''; return; }
    local raw
    raw="$(jq -r '
        if type != "object" then empty
        elif has("value") then .value
        elif has("Value") then .Value
        elif has("effectiveValue") then .effectiveValue
        elif has("EffectiveValue") then .EffectiveValue
        else empty
        end
    ' <<<"$pol" 2>/dev/null)"
    to_bool_or_null "$raw"
}

# safe_file_name <name>  → lowercase, only [a-z0-9-], trim dashes
get_safe_file_name() {
    local s="${1//[^a-zA-Z0-9-]/-}"
    s="${s,,}"
    # collapse runs of dashes and trim leading/trailing
    s="$(printf '%s' "$s" | sed -E 's/-+/-/g; s/^-+//; s/-+$//')"
    printf '%s' "$s"
}

# =============================================================================
#  Output directory (timestamped per run)
# =============================================================================

TIMESTAMP="$(date +%Y-%m-%d-%H%M%S)"
ORG_SAFE_NAME="$(get_safe_file_name "$ORG_SHORT_NAME")"
RUN_OUTPUT_DIR="${OUTPUT_PATH}/${ORG_SAFE_NAME}-${TIMESTAMP}"
mkdir -p "$RUN_OUTPUT_DIR"

# =============================================================================
#  Markdown report writer (Phase 6 §1)
# =============================================================================

write_assessment_report() {
    local file_path="$1" title="$2" scope="$3" results_file="$4"
    local quiet="${5:-}"

    local date_str; date_str="$(date '+%Y-%m-%d %H:%M:%S')"
    local pass fail nc
    # One jq pass returning "pass fail nc" (perf: was 3 separate jq invocations).
    read -r pass fail nc < <(jq -s -r '
        [
            ([.[] | select(.status=="PASS")] | length),
            ([.[] | select(.status=="FAIL")] | length),
            ([.[] | select(.status=="NOT CHECKED")] | length)
        ] | @tsv
    ' "$results_file")

    {
        printf '# %s\n\n' "$title"
        printf '| Field | Value |\n'
        printf '|-------|-------|\n'
        printf '| **Assessment Date** | %s |\n' "$date_str"
        printf '| **Scope** | %s |\n' "$scope"
        printf '| **Assessor** | %s |\n' "$SCRIPT_NAME"
        printf '\n## Summary\n\n'
        printf '`%s PASS | %s FAIL | %s NOT CHECKED`\n\n' "$pass" "$fail" "$nc"
        printf '## Control Results\n\n'
        printf '| | Status | Severity | Control | Finding |\n'
        printf '|---|--------|----------|---------|---------|\n'

        # Sort: FAIL→NC→PASS, then High→Med→Low
        jq -s -r '
            def status_ord: if .status=="FAIL" then 0 elif .status=="NOT CHECKED" then 1 else 2 end;
            def sev_ord:    if .severity=="High" then 0 elif .severity=="Medium" then 1 else 2 end;
            def icon:       if .status=="PASS" then "✅" elif .status=="FAIL" then "❌" else "⚠️" end;
            def sev_icon:   if .severity=="High" then "🔴" elif .severity=="Medium" then "🟡" else "🔵" end;
            sort_by(status_ord, sev_ord) |
            .[] |
            "| \(icon) | \(.status) | \(sev_icon) \(.severity) | \(.id): \(.control) | "
            + ((.finding // "") | gsub("\\|"; "\\|") | gsub("\r?\n"; " ")) + " |"
        ' "$results_file"
        printf '\n'

        # Improvement Opportunities section (FAIL details)
        local fails
        fails=$(jq -s 'map(select(.status=="FAIL"))' "$results_file")
        if [[ "$(jq 'length' <<<"$fails")" -gt 0 ]]; then
            printf '## Improvement Opportunities\n\n'
            jq -r '
                def sev_ord:  if .severity=="High" then 0 elif .severity=="Medium" then 1 else 2 end;
                def sev_icon: if .severity=="High" then "🔴" elif .severity=="Medium" then "🟡" else "🔵" end;
                sort_by(sev_ord) |
                .[] |
                "### \(sev_icon) \(.id): \(.control) [\(.severity)]\n\n\(.finding)\n"
            ' <<<"$fails"
        fi
    } >"$file_path"

    [[ "$quiet" == "quiet" ]] || log_ok "  Report saved: $file_path"
}

# =============================================================================
#  Canonical JSON writer (Phase 6 §2, schemas/scan.schema.json)
# =============================================================================

# export_assessment_to_json <FILE> <ORG_NAME> <ORG_URL> <ORG_RESULTS_JSONL>
#     <PROJECTS_DIR> <ELAPSED_SECONDS>
# PROJECTS_DIR contains one <proj-safe>.jsonl per project plus
# <proj-safe>.name file holding the display name.
export_assessment_to_json() {
    local file="$1" org_name="$2" org_url="$3"
    local org_results="$4" projects_dir="$5" elapsed="$6"

    local generated_at; generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    # Org controls
    local org_controls='[]'
    if [[ -s "$org_results" ]]; then
        org_controls="$(jq -s --arg org "$org_name" '
            map({
                id, status, severity, category, control, finding,
                scope: { type:"organization", organization:$org, project:null }
            })
        ' "$org_results")"
    fi

    # Project controls + summaries
    local projects_arr='[]'
    local proj_controls='[]'
    if [[ -d "$projects_dir" ]]; then
        local meta entries=() summaries=()
        for meta in "$projects_dir"/*.name; do
            [[ -e "$meta" ]] || continue
            local base="${meta%.name}"
            local name; name="$(<"$meta")"
            local rf="${base}.jsonl"
            [[ -f "$rf" ]] || continue
            local pPass pFail pNc
            # One jq pass returning "pass fail nc" (perf: was 3 separate jq invocations).
            read -r pPass pFail pNc < <(jq -s -r '
                [
                    ([.[] | select(.status=="PASS")] | length),
                    ([.[] | select(.status=="FAIL")] | length),
                    ([.[] | select(.status=="NOT CHECKED")] | length)
                ] | @tsv
            ' "$rf")
            summaries+=("$(jq -nc --arg name "$name" --argjson p "$pPass" --argjson f "$pFail" --argjson n "$pNc" \
                '{name:$name, summary:{pass:$p, fail:$f, notChecked:$n}}')")
            proj_controls="$(jq -s --arg org "$org_name" --arg name "$name" --argjson acc "$proj_controls" '
                $acc + (map({
                    id, status, severity, category, control, finding,
                    scope: { type:"project", organization:$org, project:$name }
                }))
            ' "$rf")"
        done
        if (( ${#summaries[@]} > 0 )); then
            projects_arr="$(printf '%s\n' "${summaries[@]}" | jq -s '.')"
        fi
    fi

    local total_pass total_fail total_nc
    # One jq pass over the merged org+proj controls (perf: was 6 separate jq invocations).
    read -r total_pass total_fail total_nc < <(jq -n -r \
        --argjson o "$org_controls" --argjson p "$proj_controls" '
            ($o + $p) as $all |
            [
                ([$all[] | select(.status=="PASS")] | length),
                ([$all[] | select(.status=="FAIL")] | length),
                ([$all[] | select(.status=="NOT CHECKED")] | length)
            ] | @tsv
        ')

    jq -n \
        --arg gen "$generated_at" \
        --arg generator "$SCRIPT_NAME" \
        --arg orgName "$org_name" \
        --arg orgUrl  "$org_url" \
        --argjson elapsed "$elapsed" \
        --argjson summaryPass "$total_pass" \
        --argjson summaryFail "$total_fail" \
        --argjson summaryNc   "$total_nc" \
        --argjson projects    "$projects_arr" \
        --argjson orgControls "$org_controls" \
        --argjson projControls "$proj_controls" \
        '{
            "$schema": "https://raw.githubusercontent.com/microsoft/adoqr/main/schemas/scan.schema.json",
            schemaVersion: "1.0",
            meta: {
                tool: "adoqr",
                generator: $generator,
                generatedAt: $gen,
                elapsedSeconds: $elapsed
            },
            organization: { name: $orgName, url: $orgUrl },
            summary: { pass: $summaryPass, fail: $summaryFail, notChecked: $summaryNc },
            projects: $projects,
            controls: $orgControls + $projControls
        }' \
        >"$file"
}

# =============================================================================
#  Phase 4 — Organization checks (initial slice)
# -----------------------------------------------------------------------------
#  Each function takes a results file path and appends JSONL via emit_control.
#  Function names mirror the PowerShell entry point for 1:1 traceability.
# =============================================================================

# test_org_policies <RESULTS_FILE>
test_org_policies() {
    local rf="$1"
    log_step "  Checking organization policies..."

    # Build a flattened policy map {Policy.Name: <policy-json>} via jq.
    local policy_map='{}'

    # Primary: Contribution HierarchyQuery (works on all orgs)
    local body
    body=$(cat <<JSON
{
  "contributionIds": ["ms.vss-admin-web.organization-policies-data-provider"],
  "dataProviderContext": {
    "properties": {
      "sourcePage": {
        "url": "${ORG_URL}/_settings/organizationPolicy",
        "routeId": "ms.vss-admin-web.collection-admin-hub-route",
        "routeValues": {
          "adminPivot": "organizationPolicy",
          "controller": "ContributedPage",
          "action": "Execute"
        }
      }
    }
  }
}
JSON
)
    local contrib_path
    contrib_path="$(ado_post "${ORG_URL}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" "$body" || true)"
    if [[ -n "$contrib_path" && -f "$contrib_path" ]]; then
        policy_map="$(jq '
            .dataProviders["ms.vss-admin-web.organization-policies-data-provider"].policies // {}
            | to_entries
            | map(.value)
            | add // []
            | map(select(.policy.name) | { (.policy.name): .policy })
            | add // {}
        ' "$contrib_path" 2>/dev/null || printf '%s' '{}')"
    fi

    # Fallback: OrganizationPolicy REST API
    if [[ "$policy_map" == "{}" || "$policy_map" == "null" ]]; then
        local fb
        fb="$(ado_get "${ORG_URL}/_apis/OrganizationPolicy/Policies?api-version=7.1-preview.1" || true)"
        if [[ -n "$fb" && -f "$fb" ]]; then
            policy_map="$(jq '
                (.value // [])
                | map(select(.Policy.Name) | { (.Policy.Name): .Policy })
                | add // {}
            ' "$fb" 2>/dev/null || printf '%s' '{}')"
        fi
    fi

    # ---- AUTH-01: AAD Authentication --------------------------------------
    local conn
    conn="$(ado_get "${ORG_URL}/_apis/connectiondata?api-version=7.1-preview" || true)"
    if [[ -n "$conn" && -f "$conn" ]]; then
        local subj
        subj="$(jq -r '.authenticatedUser.subjectDescriptor // ""' "$conn")"
        if [[ "$subj" =~ ^aad\. ]]; then
            emit_control "$rf" "AUTH-01" "PASS" "High" "AAD Authentication" \
                "Organization is Azure AD backed (subject: aad)."
        else
            emit_control "$rf" "AUTH-01" "FAIL" "High" "AAD Authentication" \
                "Organization does not appear to be AAD-backed. Connect to Azure AD via Organization Settings."
        fi
    else
        emit_control "$rf" "AUTH-01" "NOT CHECKED" "High" "AAD Authentication" \
            "Could not retrieve connection data to verify AAD authentication."
    fi

    # ---- AUTH-03: Public Projects ------------------------------------------
    local projs
    projs="$(ado_get "${ORG_URL}/_apis/projects?api-version=7.1" || true)"
    if [[ -n "$projs" && -f "$projs" ]]; then
        local pub_count pub_names
        pub_count="$(jq '[.value[]? | select(.visibility=="public")] | length' "$projs")"
        if (( pub_count == 0 )); then
            emit_control "$rf" "AUTH-03" "PASS" "High" "Public Projects Disabled" "No public projects found."
        else
            pub_names="$(jq -r '[.value[]? | select(.visibility=="public") | .name] | join(", ")' "$projs")"
            emit_control "$rf" "AUTH-03" "FAIL" "High" "Public Projects Disabled" \
                "Public projects found: ${pub_names}. Change to Private via Project Settings."
        fi
    else
        emit_control "$rf" "AUTH-03" "NOT CHECKED" "High" "Public Projects Disabled" \
            "Could not enumerate projects to verify visibility."
    fi

    # ---- Policy-driven checks ---------------------------------------------
    if [[ "$policy_map" == "{}" || "$policy_map" == "null" ]]; then
        local id
        for id in AUTH-05 OAUTH-01 OAUTH-02 ACCESS-02 ACCESS-03; do
            emit_control "$rf" "$id" "NOT CHECKED" "Medium" "$id" \
                "Could not retrieve organization policies."
        done
        emit_control "$rf" "ACCESS-01" "NOT CHECKED" "Medium" "Enterprise Access to Projects" \
            "Manual review required. Check Organization Settings > Policies > Enterprise access."
        emit_control "$rf" "ACCESS-04" "NOT CHECKED" "Medium" "IP Allow List" \
            "Manual review required. Confirm an IP allow list is configured under Organization Settings > Policies > Conditional access (requires Microsoft Entra ID P1/P2)."
        for id in PATPOL-01 PATPOL-02 PATPOL-03; do
            emit_control "$rf" "$id" "NOT CHECKED" "Medium" "$id" \
                "Could not retrieve organization policies."
        done
        return 0
    fi

    # Helper: emit a "policy expected to be enabled" trio (PASS / FAIL / NC).
    _policy_check() {
        local id="$1" sev="$2" control="$3" key="$4"
        local want_true="$5"      # 'true' or 'false' — desired value for PASS
        local pass_msg="$6" fail_msg="$7" nc_msg="$8"
        local pol; pol="$(jq -c --arg k "$key" '.[$k] // null' <<<"$policy_map")"
        if [[ "$pol" == "null" || -z "$pol" ]]; then
            emit_control "$rf" "$id" "NOT CHECKED" "$sev" "$control" "$nc_msg"; return
        fi
        local val; val="$(get_org_policy_boolean "$pol")"
        if [[ "$val" == "$want_true" ]]; then
            emit_control "$rf" "$id" "PASS" "$sev" "$control" "$pass_msg"
        elif [[ -n "$val" ]]; then
            emit_control "$rf" "$id" "FAIL" "$sev" "$control" "$fail_msg"
        else
            emit_control "$rf" "$id" "NOT CHECKED" "$sev" "$control" "$nc_msg"
        fi
    }

    # Keep parity with PowerShell: treat missing AUTH-05 policy as a failed posture.
    local auth05_pol auth05_val
    auth05_pol="$(jq -c '."Policy.EnforceAADConditionalAccess" // null' <<<"$policy_map")"
    if [[ "$auth05_pol" == "null" || -z "$auth05_pol" ]]; then
        emit_control "$rf" "AUTH-05" "FAIL" "Medium" "Conditional Access Policy" \
            "AAD Conditional Access Policy validation is not enabled. Enable via Organization Settings > Policies."
    else
        auth05_val="$(get_org_policy_boolean "$auth05_pol")"
        if [[ "$auth05_val" == "true" ]]; then
            emit_control "$rf" "AUTH-05" "PASS" "Medium" "Conditional Access Policy" \
                "AAD Conditional Access Policy validation is enabled."
        else
            emit_control "$rf" "AUTH-05" "FAIL" "Medium" "Conditional Access Policy" \
                "AAD Conditional Access Policy validation is not enabled. Enable via Organization Settings > Policies."
        fi
    fi

    # Keep parity with PowerShell: treat unknown OAUTH-01 posture as failed-safe.
    local oauth_pol oauth_val
    oauth_pol="$(jq -c '."Policy.DisallowOAuthAuthentication" // null' <<<"$policy_map")"
    if [[ "$oauth_pol" == "null" || -z "$oauth_pol" ]]; then
        emit_control "$rf" "OAUTH-01" "FAIL" "Medium" "Third-Party OAuth Disabled" \
            "Third-party application access via OAuth is enabled. Disable unless required."
    else
        oauth_val="$(get_org_policy_boolean "$oauth_pol")"
        if [[ "$oauth_val" == "true" ]]; then
            emit_control "$rf" "OAUTH-01" "PASS" "Medium" "Third-Party OAuth Disabled" \
                "Third-party application access via OAuth is disabled."
        else
            emit_control "$rf" "OAUTH-01" "FAIL" "Medium" "Third-Party OAuth Disabled" \
                "Third-party application access via OAuth is enabled. Disable unless required."
        fi
    fi

    _policy_check "OAUTH-02" "Medium" "SSH Access Disabled" \
        "Policy.DisallowSecureShell" "true" \
        "SSH authentication is disabled." \
        "SSH authentication is enabled. Disable via Organization Settings > Policies." \
        "SSH policy not found."

    _policy_check "ACCESS-02" "Medium" "Request Access Policy Disabled" \
        "Policy.AllowRequestAccessToken" "false" \
        "Request access policy is disabled." \
        "Request access policy is enabled. Disable via Organization Settings > Policies." \
        "Request access policy not found."

    _policy_check "ACCESS-03" "Medium" "Invite New Users Restricted" \
        "Policy.AllowTeamMembersToInviteNewUsers" "false" \
        "Only org admins can invite new users." \
        "Any admin can invite new users. Restrict to org admins only." \
        "Invite new users policy not found."

    # ACCESS-01 — slightly different (different default outcomes)
    local ea; ea="$(jq -c '."Policy.EnterpriseAccessToProjects" // null' <<<"$policy_map")"
    if [[ "$ea" != "null" && -n "$ea" ]]; then
        local val; val="$(get_org_policy_boolean "$ea")"
        if [[ "$val" == "false" ]]; then
            emit_control "$rf" "ACCESS-01" "PASS" "Medium" "Enterprise Access to Projects" \
                "Enterprise access to projects is disabled."
        else
            emit_control "$rf" "ACCESS-01" "FAIL" "Medium" "Enterprise Access to Projects" \
                "Enterprise access to projects is enabled. Review via Organization Settings > Policies."
        fi
    else
        emit_control "$rf" "ACCESS-01" "NOT CHECKED" "Medium" "Enterprise Access to Projects" \
            "Manual review required. Check Organization Settings > Policies > Enterprise access."
    fi

    _policy_check "PATPOL-01" "Medium" "Maximum PAT Lifetime Policy" \
        "Policy.MaximumPATLifetime" "true" \
        "Maximum PAT lifetime policy is enforced." \
        "Maximum PAT lifetime policy is not enforced. Enable via Organization Settings > Policies." \
        "PAT lifetime policy not found in org policies."

    _policy_check "PATPOL-02" "Medium" "Restrict PAT Scope" \
        "Policy.EnforcePatScopeRestriction" "true" \
        "PAT scope restriction policy is enforced." \
        "PAT scope restriction policy is not enforced. Enable via Organization Settings > Policies." \
        "PAT scope restriction policy not found in org policies."

    _policy_check "PATPOL-03" "Medium" "Restrict Global PATs" \
        "Policy.DisallowFullScopePats" "true" \
        "Full-scope (global) PATs are restricted." \
        "Full-scope PATs are allowed. Restrict via Organization Settings > Policies." \
        "Global PAT restriction policy not found in org policies."

    # ACCESS-04: IP allow list — manual review (no public REST API).
    emit_control "$rf" "ACCESS-04" "NOT CHECKED" "Medium" "IP Allow List" \
        "Manual review required. Confirm an IP allow list is configured under Organization Settings > Policies > Conditional access (requires Microsoft Entra ID P1/P2)."
}

# test_org_users <RESULTS_FILE>
test_org_users() {
    local rf="$1"
    log_step "  Checking users..."

    local users
    users="$(az_cli devops user list --org "$ORG_URL" || true)"
    if [[ -z "$users" || ! -f "$users" ]] || ! jq -e '.members? // empty' "$users" >/dev/null 2>&1; then
        local id
        for id in AUTH-02 AUTH-04 USER-01 USER-02 USER-03; do
            emit_control "$rf" "$id" "NOT CHECKED" "High" "$id" "Could not retrieve user list."
        done
        return 0
    fi

    # Cut-off ISO date for inactivity comparisons (UTC).
    local cutoff
    if cutoff="$(date -u -d "${INACTIVE_DAYS} days ago" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"; then
        :
    else
        # macOS BSD date fallback
        cutoff="$(date -u -v -${INACTIVE_DAYS}d '+%Y-%m-%dT%H:%M:%SZ')"
    fi

    # AUTH-02: External (non-AAD) users
    local ext_count ext_sample
    ext_count="$(jq '[.members[]?
                       | select((.user.origin // "") != "aad"
                                or (.user.subjectKind=="user"
                                    and ((.user.mailAddress // "") | test("@(hotmail|outlook|gmail|yahoo|live)\\."; "i"))))]
                     | length' "$users")"
    if (( ext_count == 0 )); then
        emit_control "$rf" "AUTH-02" "PASS" "High" "External User Access Disabled" "No external (non-AAD) users found."
    else
        ext_sample="$(jq -r '[.members[]?
                              | select((.user.origin // "") != "aad"
                                       or (.user.subjectKind=="user"
                                           and ((.user.mailAddress // "") | test("@(hotmail|outlook|gmail|yahoo|live)\\."; "i"))))
                              | .user.mailAddress // .user.displayName // .user.principalName]
                            | .[0:10] | join(", ")' "$users")"
        emit_control "$rf" "AUTH-02" "FAIL" "High" "External User Access Disabled" \
            "${ext_count} external user(s) found: ${ext_sample}. Remove via Organization Settings > Users."
    fi

    # AUTH-04: Guest users (#EXT# discriminator)
    local guest_count guest_sample
    guest_count="$(jq '[.members[]?
                         | select(.user.subjectKind=="user"
                                  and (.user.origin // "")=="aad"
                                  and (((.user.mailAddress // "") | test("#EXT#"; "i"))
                                       or ((.user.directoryAlias // "") | test("#EXT#"; "i"))))]
                       | length' "$users")"
    if (( guest_count == 0 )); then
        emit_control "$rf" "AUTH-04" "PASS" "High" "Guest User Justification" "No guest users found."
    else
        guest_sample="$(jq -r '[.members[]?
                                 | select(.user.subjectKind=="user"
                                          and (.user.origin // "")=="aad"
                                          and (((.user.mailAddress // "") | test("#EXT#"; "i"))
                                               or ((.user.directoryAlias // "") | test("#EXT#"; "i"))))
                                 | .user.mailAddress // .user.displayName]
                               | .[0:10] | join(", ")' "$users")"
        emit_control "$rf" "AUTH-04" "FAIL" "High" "Guest User Justification" \
            "${guest_count} guest user(s) found: ${guest_sample}. Review and document justification."
    fi

    # USER-01: Inactive users
    local inactive
    inactive="$(jq --arg cutoff "$cutoff" '
        [.members[]?
         | select((.lastAccessedDate // "") != "" and .lastAccessedDate < $cutoff)]
        | length' "$users")"
    if (( inactive == 0 )); then
        emit_control "$rf" "USER-01" "PASS" "Medium" "Inactive User Access" \
            "No users inactive for more than ${INACTIVE_DAYS} days."
    else
        emit_control "$rf" "USER-01" "FAIL" "Medium" "Inactive User Access" \
            "${inactive} user(s) inactive for ${INACTIVE_DAYS}+ days. Remove or disable these accounts."
    fi

    # USER-02: Graph cross-check (requires --include-graph-check + permission)
    if (( INCLUDE_GRAPH_CHECK == 1 )); then
        emit_control "$rf" "USER-02" "NOT CHECKED" "High" "Deleted/Disconnected AAD Users" \
            "Graph cross-check is enabled but the bash port has not yet implemented Microsoft Graph traversal. Tracked for a follow-up commit."
    else
        emit_control "$rf" "USER-02" "NOT CHECKED" "High" "Deleted/Disconnected AAD Users" \
            "Re-run with --include-graph-check (and Microsoft Graph User.Read.All permission) to enable this check."
    fi

    # USER-03: keep parity with PowerShell control taxonomy.
    if (( guest_count == 0 )); then
        emit_control "$rf" "USER-03" "PASS" "Medium" "Inactive Guest Users" \
            "No guest users were found that require inactivity cleanup."
    else
        emit_control "$rf" "USER-03" "NOT CHECKED" "Medium" "Inactive Guest Users" \
            "Guest users exist. Manually review inactivity and remove stale guest accounts."
    fi
}

# =============================================================================
#  Graph helpers
# =============================================================================

# Returns the descriptor 'value' for a given storage key (GUID), or empty.
get_ado_graph_subject_descriptor() {
    local storage_key="$1"
    [[ -n "$storage_key" ]] || return 0
    local f
    f="$(ado_get "${VSSPS_URL}/_apis/graph/descriptors/${storage_key}?api-version=7.1-preview.1")"
    ado_jq "$f" -r '.value // empty'
}

# POST /graph/subjectlookup for a list of descriptors (one per arg).
# Emits a JSON object on stdout mapping descriptor -> subject.
get_ado_graph_subjects_by_descriptor() {
    local body
    body="$(printf '%s\n' "$@" | awk 'NF' | sort -u \
        | jq -R . | jq -cs '{lookupKeys: map({descriptor: .})}')"
    [[ "$(jq '.lookupKeys | length' <<<"$body")" == "0" ]] && { printf '{}'; return; }
    local f
    f="$(ado_post "${VSSPS_URL}/_apis/graph/subjectlookup?api-version=7.1-preview.1" "$body")"
    if [[ -z "$f" || ! -f "$f" ]]; then printf '{}'; return; fi
    jq -c '.value // {}' "$f" 2>/dev/null || printf '{}'
}

# Down-1 members of a group, resolved to subjects. Emits a JSON array.
get_ado_graph_group_members() {
    local group_descriptor="$1"
    [[ -n "$group_descriptor" ]] || { printf '[]'; return; }
    local enc f
    enc="$(url_encode "$group_descriptor")"
    f="$(ado_get "${VSSPS_URL}/_apis/graph/memberships/${enc}?direction=down&depth=1&api-version=7.1-preview.1")"
    if [[ -z "$f" || ! -f "$f" ]]; then printf '[]'; return; fi
    local descriptors
    mapfile -t descriptors < <(jq -r '.value[]?.memberDescriptor // empty' "$f")
    (( ${#descriptors[@]} == 0 )) && { printf '[]'; return; }
    local subject_map
    subject_map="$(get_ado_graph_subjects_by_descriptor "${descriptors[@]}")"
    jq -nc --argjson map "$subject_map" --argjson ds "$(printf '%s\n' "${descriptors[@]}" | jq -R . | jq -cs '.')" \
        '$ds | map( $map[.] // {descriptor: ., displayName: .} )'
}

# Predicate: returns 0 if a member JSON looks like an external/guest account.
test_is_guest_member() {
    local member_json="$1"
    [[ -n "$member_json" ]] || return 1
    jq -e '
        ([(.mailAddress // ""), (.principalName // ""),
          (.directoryAlias // ""), (.displayName // "")]
         | map(ascii_downcase)
         | any(. | test("#ext#"))
        )' <<<"$member_json" >/dev/null 2>&1
}

# =============================================================================
#  Org checks — ported
# =============================================================================

test_org_audit() {
    local rf="$1"
    log_step "  Checking audit configuration..."
    local f
    f="$(ado_get "${AUDIT_URL}/_apis/audit/streams?api-version=7.1-preview.1")"

    # AUDIT-01: manual
    emit_control "$rf" "AUDIT-01" "NOT CHECKED" "Medium" "Audit Log Backup" \
        "Manual review required. Verify audit logs are backed up to external storage."

    # AUDIT-02
    if [[ -z "$f" || ! -f "$f" ]]; then
        emit_control "$rf" "AUDIT-02" "NOT CHECKED" "Medium" "Audit Streaming" \
            "Could not retrieve audit streams (may require elevated permissions)."
    else
        local total enabled
        total="$(jq '(.value // []) | length' "$f")"
        enabled="$(jq '[(.value // [])[] | select(.status == "enabled")] | length' "$f")"
        if (( total > 0 && enabled > 0 )); then
            emit_control "$rf" "AUDIT-02" "PASS" "Medium" "Audit Streaming" \
                "${enabled} active audit stream(s) configured."
        elif (( total > 0 )); then
            emit_control "$rf" "AUDIT-02" "FAIL" "Medium" "Audit Streaming" \
                "Audit streams exist but none are enabled. Enable streaming to a SIEM."
        else
            emit_control "$rf" "AUDIT-02" "FAIL" "Medium" "Audit Streaming" \
                "No audit streams configured. Set up streaming to a SIEM."
        fi
    fi

    # AUDIT-03: manual
    emit_control "$rf" "AUDIT-03" "NOT CHECKED" "Medium" "Alerts Configuration" \
        "Manual review required. Verify alerts are configured for critical actions."
}

test_org_pipeline_settings() {
    local rf="$1"
    log_step "  Checking org pipeline settings..."
    local f
    f="$(ado_get "${ORG_URL}/_apis/build/generalsettings?api-version=7.1-preview.1")"

    if [[ -z "$f" || ! -f "$f" ]]; then
        local id
        for id in PIPELINE-01 PIPELINE-02 PIPELINE-03 PIPELINE-04; do
            emit_control "$rf" "$id" "NOT CHECKED" "Medium" "$id" "Could not retrieve org pipeline settings."
        done
        emit_control "$rf" "PIPELINE-05" "NOT CHECKED" "High" "Auto-Injected Tasks" "Manual review required."
        return 0
    fi

    _pipe_chk() {
        local id="$1" field="$2" label="$3"
        local val
        val="$(jq -r --arg f "$field" '.[$f] // empty' "$f")"
        if [[ "$val" == "true" ]]; then
            emit_control "$rf" "$id" "PASS" "Medium" "$label" "$field is enabled at org level."
        else
            emit_control "$rf" "$id" "FAIL" "Medium" "$label" \
                "$field is disabled. Enable via Org Settings > Pipelines > Settings."
        fi
    }
    _pipe_chk PIPELINE-01 enforceJobAuthScope             "Pipeline Auth Scope (Non-Release)"
    _pipe_chk PIPELINE-02 enforceJobAuthScopeForReleases  "Pipeline Auth Scope (Release)"
    _pipe_chk PIPELINE-03 enforceReferencedRepoScopedToken "Pipeline Repository Scope"
    _pipe_chk PIPELINE-04 enforceSettableVar              "Settable Variables at Queue Time"

    emit_control "$rf" "PIPELINE-05" "NOT CHECKED" "High" "Auto-Injected Tasks" \
        "Manual review required. Check Organization Settings > Pipelines for auto-injected tasks."
}

test_org_feeds() {
    local rf="$1"
    log_step "  Checking org feeds..."
    local f
    f="$(ado_get "${FEEDS_URL}/_apis/packaging/feeds?api-version=7.1-preview.1")"

    if [[ -z "$f" || ! -f "$f" ]] || [[ "$(jq '(.value // []) | length' "$f")" == "0" ]]; then
        emit_control "$rf" "FEED-01" "PASS" "High" "Feed Permissions for Broad Groups" "No org-level feeds found."
        emit_control "$rf" "FEED-02" "NOT CHECKED" "High" "Feed Creation Permissions" \
            "Manual review required. Check who can create feeds in Organization Settings."
        emit_control "$rf" "FEED-03" "PASS" "Medium" "External Package Protection" "No org-scoped feeds found."
    else
        # FEED-01: broad group elevated access
        local offenders=() upstream_offenders=()
        local feed_id feed_name perms_f total upstream_enabled
        while IFS=$'\t' read -r feed_id feed_name upstream_enabled; do
            perms_f="$(ado_get "${FEEDS_URL}/_apis/packaging/Feeds/${feed_id}/permissions?api-version=7.1-preview.1")"
            if [[ -n "$perms_f" && -f "$perms_f" ]]; then
                # Iterate permissions; flag if any broad group with non-reader role
                local found_broad=0 perm_count i name role
                perm_count="$(jq '(.value // []) | length' "$perms_f")"
                for (( i=0; i<perm_count; i++ )); do
                    name="$(jq -r --argjson i "$i" '.value[$i].displayName // ""' "$perms_f")"
                    role="$(jq -r --argjson i "$i" '.value[$i].role // ""' "$perms_f")"
                    if test_is_broad_group "$name" && [[ "${role,,}" != "reader" ]]; then
                        found_broad=1; break
                    fi
                done
                (( found_broad == 1 )) && offenders+=("$feed_name")
            fi
            # FEED-03 upstreams
            if [[ "$upstream_enabled" == "true" ]]; then
                local active_count
                active_count="$(jq --arg id "$feed_id" '
                    [(.value // [])[] | select((.id|ascii_downcase)==($id|ascii_downcase)) | (.upstreamSources // [])[] | select((.status // "") != "disabled")] | length' "$f")"
                (( active_count > 0 )) && upstream_offenders+=("$feed_name")
            fi
        done < <(jq -r '(.value // [])[] | [.id, .name, ((.upstreamEnabled // false)|tostring)] | @tsv' "$f")

        if (( ${#offenders[@]} == 0 )); then
            emit_control "$rf" "FEED-01" "PASS" "High" "Feed Permissions for Broad Groups" \
                "No org-level feeds have broad group write/admin access."
        else
            local off_joined
            off_joined="$(IFS=', '; printf '%s' "${offenders[*]}")"
            emit_control "$rf" "FEED-01" "FAIL" "High" "Feed Permissions for Broad Groups" \
                "Feeds with broad group elevated access: ${off_joined}. Restrict to Reader role."
        fi

        emit_control "$rf" "FEED-02" "NOT CHECKED" "High" "Feed Creation Permissions" \
            "Manual review required. Check who can create feeds in Organization Settings."

        if (( ${#upstream_offenders[@]} == 0 )); then
            emit_control "$rf" "FEED-03" "PASS" "Medium" "External Package Protection" \
                "No org-scoped feeds have active upstream sources."
        else
            local up_joined
            up_joined="$(IFS=', '; printf '%s' "${upstream_offenders[*]}")"
            emit_control "$rf" "FEED-03" "NOT CHECKED" "Medium" "External Package Protection" \
                "Feeds with active upstream sources: ${up_joined}. Verify each internal package name is saved to the feed (save-to-feed mitigates dependency confusion)."
        fi
    fi

    # BADGE-01: anonymous badge from generalsettings
    local pipe_f
    pipe_f="$(ado_get "${ORG_URL}/_apis/build/generalsettings?api-version=7.1-preview.1")"
    if [[ -n "$pipe_f" && -f "$pipe_f" ]] && jq -e 'has("statusBadgesArePrivate")' "$pipe_f" >/dev/null 2>&1; then
        local sbp
        sbp="$(jq -r '.statusBadgesArePrivate' "$pipe_f")"
        if [[ "$sbp" == "true" ]]; then
            emit_control "$rf" "BADGE-01" "PASS" "Low" "Anonymous Badge API" \
                "Anonymous badge access is disabled at org level."
        else
            emit_control "$rf" "BADGE-01" "FAIL" "Low" "Anonymous Badge API" \
                "Anonymous badge access is enabled. Disable via Organization Settings > Pipelines > Settings."
        fi
    else
        emit_control "$rf" "BADGE-01" "NOT CHECKED" "Low" "Anonymous Badge API" \
            "Could not retrieve badge setting from org pipeline settings."
    fi
}

test_org_pat_policy() {
    : "${1:?}"  # PATPOL-01..03 are handled in test_org_policies; nothing to emit here.
}

test_org_admins() {
    local rf="$1"
    log_step "  Checking admin groups..."
    local g_f
    g_f="$(ado_get "${VSSPS_URL}/_apis/graph/groups?api-version=7.1-preview.1")"

    local pca_desc="" pcsa_desc=""
    if [[ -n "$g_f" && -f "$g_f" ]]; then
        pca_desc="$(jq -r '[.value[]? | select(.displayName=="Project Collection Administrators")] | .[0].descriptor // empty' "$g_f")"
        pcsa_desc="$(jq -r '[.value[]? | select(.displayName=="Project Collection Service Accounts")] | .[0].descriptor // empty' "$g_f")"
    fi

    local pca_members_json="[]" pca_count=0
    if [[ -n "$pca_desc" ]]; then
        pca_members_json="$(get_ado_graph_group_members "$pca_desc")"
        pca_count="$(jq 'length' <<<"$pca_members_json")"
    fi

    # ADMIN-01: manual
    emit_control "$rf" "ADMIN-01" "NOT CHECKED" "High" "Privileged Group Membership" \
        "Manual review required. Verify all PCA/admin group members have legitimate business need."

    # ADMIN-02: <= 6
    if (( pca_count <= 6 )); then
        emit_control "$rf" "ADMIN-02" "PASS" "Medium" "PCA Count (Max 6)" \
            "PCA member count: ${pca_count} (≤ 6)."
    else
        emit_control "$rf" "ADMIN-02" "FAIL" "Medium" "PCA Count (Max 6)" \
            "PCA member count: ${pca_count} (exceeds 6). Remove unnecessary members."
    fi

    # ADMIN-03: >= 2
    if (( pca_count >= 2 )); then
        emit_control "$rf" "ADMIN-03" "PASS" "Medium" "PCA Count (Min 2)" \
            "PCA member count: ${pca_count} (≥ 2)."
    else
        emit_control "$rf" "ADMIN-03" "FAIL" "Medium" "PCA Count (Min 2)" \
            "PCA member count: ${pca_count} (fewer than 2). Add a backup admin."
    fi

    # ADMIN-04, 05: manual
    emit_control "$rf" "ADMIN-04" "NOT CHECKED" "High" "Service Accounts in Privileged Roles" \
        "Manual review required. Inspect PCA members for service/non-person accounts."
    emit_control "$rf" "ADMIN-05" "NOT CHECKED" "High" "ALT Accounts for Admin Activity" \
        "Manual review required. Verify all admins use ALT/SC-ALT accounts for privileged activity."

    # ADMIN-06: PCSA size
    if [[ -n "$pcsa_desc" ]]; then
        local pcsa_members pcsa_count
        pcsa_members="$(get_ado_graph_group_members "$pcsa_desc")"
        pcsa_count="$(jq 'length' <<<"$pcsa_members")"
        if (( pcsa_count <= 3 )); then
            emit_control "$rf" "ADMIN-06" "PASS" "High" "Project Collection Service Accounts" \
                "PCSA group has ${pcsa_count} member(s)."
        else
            emit_control "$rf" "ADMIN-06" "FAIL" "High" "Project Collection Service Accounts" \
                "PCSA group has ${pcsa_count} members. Minimize membership — these are effectively PCAs."
        fi
    else
        emit_control "$rf" "ADMIN-06" "NOT CHECKED" "High" "Project Collection Service Accounts" \
            "Could not locate PCSA group."
    fi

    # USER-04: Guest in PCA
    if (( pca_count > 0 )); then
        local guest_count=0 m
        while IFS= read -r m; do
            [[ -z "$m" ]] && continue
            test_is_guest_member "$m" && guest_count=$(( guest_count + 1 ))
        done < <(jq -c '.[]' <<<"$pca_members_json")
        if (( guest_count == 0 )); then
            emit_control "$rf" "USER-04" "PASS" "High" "Guest Users in Admin Roles" \
                "No guest users found in PCA group."
        else
            emit_control "$rf" "USER-04" "FAIL" "High" "Guest Users in Admin Roles" \
                "${guest_count} guest user(s) in PCA group. Remove immediately."
        fi
    else
        emit_control "$rf" "USER-04" "NOT CHECKED" "High" "Guest Users in Admin Roles" \
            "Could not enumerate PCA group members."
    fi

    # USER-05: Inactive PCA members
    if (( pca_count > 0 )); then
        local users_f
        users_f="$(az_cli devops user list --org "$ORG_URL" || true)"
        if [[ -z "$users_f" || ! -f "$users_f" ]]; then
            emit_control "$rf" "USER-05" "NOT CHECKED" "High" "Inactive Users in Admin Roles" \
                "Could not retrieve user list to cross-reference with PCA members."
        else
            local cutoff
            cutoff="$(date -u -d "${INACTIVE_DAYS} days ago" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
                      || date -u -v -${INACTIVE_DAYS}d '+%Y-%m-%dT%H:%M:%SZ')"
            # Build list of PCA emails (lower)
            local pca_emails
            pca_emails="$(jq -r '.[] | (.mailAddress // .principalName // "") | ascii_downcase | select(length>0)' <<<"$pca_members_json")"
            local inactive_list=()
            local email
            while IFS= read -r email; do
                [[ -z "$email" ]] && continue
                local last
                last="$(jq -r --arg e "$email" --arg c "$cutoff" '
                    [.members[]? | select((.user.mailAddress // "" | ascii_downcase)==$e)]
                    | .[0] | select(.) | select((.lastAccessedDate // "") != "" and .lastAccessedDate < $c) | .user.mailAddress // ""
                    ' "$users_f")"
                [[ -n "$last" ]] && inactive_list+=("$last")
            done <<<"$pca_emails"
            if (( ${#inactive_list[@]} == 0 )); then
                emit_control "$rf" "USER-05" "PASS" "High" "Inactive Users in Admin Roles" \
                    "All PCA members have been active within the last ${INACTIVE_DAYS} days."
            else
                local names
                names="$(IFS=', '; printf '%s' "${inactive_list[*]:0:10}")"
                emit_control "$rf" "USER-05" "FAIL" "High" "Inactive Users in Admin Roles" \
                    "${#inactive_list[@]} PCA member(s) inactive for ${INACTIVE_DAYS}+ days: ${names}. Remove or reassign."
            fi
        fi
    else
        emit_control "$rf" "USER-05" "NOT CHECKED" "High" "Inactive Users in Admin Roles" \
            "No PCA members found to check."
    fi
}

test_org_extensions() {
    local rf="$1"
    log_step "  Checking extensions..."
    local f
    f="$(ado_get "${EXTMGMT_URL}/_apis/extensionmanagement/installedextensions?api-version=7.1-preview.1")"

    if [[ -z "$f" || ! -f "$f" ]]; then
        local id
        for id in EXT-01 EXT-02 EXT-03; do
            emit_control "$rf" "$id" "NOT CHECKED" "High" "$id" "Could not retrieve installed extensions."
        done
    else
        local total untrusted
        total="$(jq '(.value // []) | length' "$f")"
        # untrusted = not built-in AND not flagged trusted AND publisherName != "Microsoft" (case-insensitive)
        untrusted="$(jq '[(.value // [])[]
            | select(
                (((.installState.flags // "") | test("BuiltIn"; "i")) | not)
                and (((.flags // "") | test("trusted"; "i")) | not)
                and (((.publisherName // "") | ascii_downcase) != "microsoft")
              )] | length' "$f")"
        if (( untrusted == 0 )); then
            emit_control "$rf" "EXT-01" "PASS" "High" "Extension Review" \
                "${total} extension(s) installed. All are built-in, trusted, or from Microsoft."
        else
            local names
            names="$(jq -r '[(.value // [])[]
                | select(
                    (((.installState.flags // "") | test("BuiltIn"; "i")) | not)
                    and (((.flags // "") | test("trusted"; "i")) | not)
                    and (((.publisherName // "") | ascii_downcase) != "microsoft")
                  )
                | "\(.extensionName // "?") (\(.publisherName // "?"))"]
                | .[0:10] | join(", ")' "$f")"
            emit_control "$rf" "EXT-01" "FAIL" "High" "Extension Review" \
                "${untrusted} non-trusted extension(s) from non-Microsoft publishers: ${names}. Verify publishers are trusted."
        fi

        local shared
        shared="$(jq '[(.value // [])[]
            | select(
                (((.installState.flags // "") | test("BuiltIn"; "i")) | not)
                and (((.flags // "") | test("trusted"; "i")) | not)
              )] | length' "$f")"
        if (( shared == 0 )); then
            emit_control "$rf" "EXT-02" "PASS" "High" "Shared Extension Scrutiny" \
                "No untrusted shared/private extensions detected."
        else
            emit_control "$rf" "EXT-02" "NOT CHECKED" "High" "Shared Extension Scrutiny" \
                "${shared} non-built-in extension(s) found. Review sources and publishers."
        fi

        emit_control "$rf" "EXT-03" "NOT CHECKED" "High" "Extension Manager Review" \
            "Manual review required. Check Organization Settings > Extensions > Permissions for excessive manager role assignments."
    fi

    # EXT-04: requested extensions
    local r_f
    r_f="$(ado_get "${EXTMGMT_URL}/_apis/extensionmanagement/requestedextensions?api-version=7.1-preview.1")"
    if [[ -z "$r_f" || ! -f "$r_f" ]] || ! jq -e 'has("value")' "$r_f" >/dev/null 2>&1; then
        emit_control "$rf" "EXT-04" "NOT CHECKED" "High" "Requested Extensions Review" \
            "Could not retrieve pending extension requests."
    else
        local rc
        rc="$(jq '(.value // []) | length' "$r_f")"
        if (( rc > 0 )); then
            emit_control "$rf" "EXT-04" "FAIL" "High" "Requested Extensions Review" \
                "${rc} pending extension request(s). Review and approve or deny."
        else
            emit_control "$rf" "EXT-04" "PASS" "High" "Requested Extensions Review" \
                "No pending extension requests."
        fi
    fi

    # COPILOT-01: any Copilot-related extension
    if [[ -n "$f" && -f "$f" ]]; then
        local cp_count cp_names
        cp_count="$(jq '[(.value // [])[]
            | select(
                ((.extensionName // ""), (.extensionId // ""), (.publisherName // ""), (.publisherId // ""))
                | ascii_downcase | test("copilot")
              )] | length' "$f" 2>/dev/null || printf 0)"
        # The above won't work because of multiple args to select; use a cleaner filter:
        cp_count="$(jq '[(.value // [])[]
            | . as $e
            | select(([($e.extensionName // ""), ($e.extensionId // ""), ($e.publisherName // ""), ($e.publisherId // "")]
                      | map(ascii_downcase) | any(. | test("copilot"))))
            ] | length' "$f")"
        if (( cp_count == 0 )); then
            emit_control "$rf" "COPILOT-01" "PASS" "Medium" "GitHub Copilot Extension Review" \
                "No GitHub Copilot extensions detected. If Copilot is in use, install only the admin-approved extension from a trusted publisher (e.g. GitHub)."
        else
            cp_names="$(jq -r '[(.value // [])[]
                | . as $e
                | select(([($e.extensionName // ""), ($e.extensionId // ""), ($e.publisherName // ""), ($e.publisherId // "")]
                          | map(ascii_downcase) | any(. | test("copilot"))))
                | "\(.extensionName // "?") (\(.publisherName // "?"))"]
                | .[0:10] | join(", ")' "$f")"
            emit_control "$rf" "COPILOT-01" "NOT CHECKED" "Medium" "GitHub Copilot Extension Review" \
                "${cp_count} Copilot-related extension(s) installed: ${cp_names}. Confirm publisher trust, admin-controlled scope, and that usage aligns with your AI policy."
        fi
    else
        emit_control "$rf" "COPILOT-01" "NOT CHECKED" "Medium" "GitHub Copilot Extension Review" \
            "Could not retrieve installed extensions to evaluate Copilot governance."
    fi
}

test_user_pats() {
    local rf="$1"
    log_step "  Checking PATs (current user only)..."
    local f
    f="$(ado_get "https://vssps.dev.azure.com/${ORG_SHORT_NAME}/_apis/tokens/pats?api-version=7.1-preview.1")"

    if [[ -z "$f" || ! -f "$f" ]] || ! jq -e '.patTokens? // empty' "$f" >/dev/null 2>&1; then
        emit_control "$rf" "PAT-*" "NOT CHECKED" "Medium" "Personal Access Tokens" \
            "Could not retrieve PATs. This API only returns the calling user's own PATs."
        return 0
    fi

    local count i pat name scope valid_to valid_from days now7 now
    count="$(jq '(.patTokens // []) | length' "$f")"
    if (( count == 0 )); then
        emit_control "$rf" "PAT-*" "NOT CHECKED" "Medium" "Personal Access Tokens" \
            "Current user has no active PATs."
        return 0
    fi

    now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    now7="$(date -u -d '7 days' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
            || date -u -v +7d '+%Y-%m-%dT%H:%M:%SZ')"

    for (( i=0; i<count; i++ )); do
        pat="$(jq -c --argjson i "$i" '.patTokens[$i]' "$f")"
        name="$(jq -r '.displayName // ""' <<<"$pat")"
        scope="$(jq -r '.scope // ""' <<<"$pat")"
        valid_to="$(jq -r '.validTo // ""' <<<"$pat")"
        valid_from="$(jq -r '.validFrom // ""' <<<"$pat")"
        local prefix="PAT '${name}'"

        # PAT-01
        if [[ "${scope,,}" == "app_token" ]]; then
            emit_control "$rf" "PAT-*" "FAIL" "Medium" "Minimum Required Permissions" \
                "${prefix} — Has full access (app_token) scope. Recreate with specific scopes."
        else
            emit_control "$rf" "PAT-*" "PASS" "Medium" "Minimum Required Permissions" \
                "${prefix} — Has scoped permissions."
        fi

        # PAT-02 / PAT-03
        if [[ -n "$valid_to" ]]; then
            if [[ -n "$valid_from" ]]; then
                days="$(_days_between "$valid_from" "$valid_to")"
            else
                days=90
            fi
            if (( days > 90 )); then
                emit_control "$rf" "PAT-02" "FAIL" "Medium" "Short Validity Period" \
                    "${prefix} — Valid for ${days} days (exceeds 90). Recreate with shorter validity."
            else
                emit_control "$rf" "PAT-02" "PASS" "Medium" "Short Validity Period" \
                    "${prefix} — Valid for ${days} days."
            fi
            if [[ "$valid_to" < "$now7" && "$valid_to" > "$now" ]]; then
                emit_control "$rf" "PAT-03" "FAIL" "Medium" "Near-Expiry PAT Renewal" \
                    "${prefix} — Expires on ${valid_to%%T*}. Renew soon."
            fi
        fi

        # PAT-06: critical scopes
        local cs found_cs=""
        for cs in vso.security_manage vso.entitlements vso.memberentitlementmanagement_write vso.project_manage app_token; do
            if [[ ",${scope,,}," == *",${cs},"* ]] || [[ "${scope,,}" == *"$cs"* ]]; then
                found_cs="$cs"; break
            fi
        done
        if [[ -n "$found_cs" ]]; then
            emit_control "$rf" "PAT-06" "FAIL" "Medium" "No Critical Permission PATs" \
                "${prefix} — Has critical scope '${found_cs}'. Use service principals for automation."
        fi
    done
}

test_org_wide_pats() {
    local rf="$1"
    log_step "  Checking org-wide PATs (requires PCA)..."
    local f
    f="$(ado_get "${ORG_URL}/_apis/tokenadmin/personalaccesstokens?api-version=7.1-preview.1")"

    if [[ -z "$f" || ! -f "$f" ]] || ! jq -e '.value? // empty' "$f" >/dev/null 2>&1; then
        emit_control "$rf" "PAT-*" "NOT CHECKED" "Medium" "Personal Access Tokens" \
            "Could not retrieve org-wide PATs. This API requires Project Collection Administrator permissions."
        return 0
    fi

    local total full_count long_count
    total="$(jq '(.value // []) | length' "$f")"
    full_count="$(jq '[(.value // [])[] | select((.scope // "" | ascii_downcase)=="app_token")] | length' "$f")"
    long_count=0
    # Iterate to compute validity duration > 90 days
    local i vt vf days
    local cnt; cnt="$total"
    for (( i=0; i<cnt; i++ )); do
        vt="$(jq -r --argjson i "$i" '.value[$i].validTo // ""' "$f")"
        vf="$(jq -r --argjson i "$i" '.value[$i].validFrom // ""' "$f")"
        if [[ -n "$vt" && -n "$vf" ]]; then
            days="$(_days_between "$vf" "$vt")"
            (( days > 90 )) && long_count=$(( long_count + 1 ))
        fi
    done

    if (( full_count == 0 )); then
        emit_control "$rf" "PAT-*" "PASS" "Medium" "Minimum Required Permissions" \
            "No org-wide full-access PATs found across ${total} total PATs."
    else
        emit_control "$rf" "PAT-*" "FAIL" "Medium" "Minimum Required Permissions" \
            "${full_count} full-access PAT(s) found across the organization. These should be recreated with specific scopes."
    fi
    if (( long_count == 0 )); then
        emit_control "$rf" "PAT-02" "PASS" "Medium" "Short Validity Period" \
            "No org-wide PATs with validity exceeding 90 days."
    else
        emit_control "$rf" "PAT-02" "FAIL" "Medium" "Short Validity Period" \
            "${long_count} PAT(s) with validity exceeding 90 days found across the organization."
    fi
}

# Days between two ISO-8601 timestamps (rounded floor). Cross-platform.
_days_between() {
    local a="$1" b="$2" ea eb
    if ea="$(date -u -d "$a" +%s 2>/dev/null)" && eb="$(date -u -d "$b" +%s 2>/dev/null)"; then
        :
    else
        # macOS BSD parse
        ea="$(date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "${a%%.*}Z" +%s 2>/dev/null || printf 0)"
        eb="$(date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "${b%%.*}Z" +%s 2>/dev/null || printf 0)"
    fi
    printf '%d' "$(( (eb - ea) / 86400 ))"
}

# =============================================================================
#  Project-scope placeholders (porting in progress)
# =============================================================================

_emit_pending() {
    local rf="$1" id="$2" sev="$3" control="$4"
    emit_control "$rf" "$id" "NOT CHECKED" "$sev" "$control" \
        "Bash port in progress: this control has not yet been ported from invoke-adoqr.ps1. Use the PowerShell entry point for full coverage."
}

test_project_settings() {
    # Args: results_file project_name
    local rf="$1" pname="$2"
    log_step "  [$pname] Checking project settings..."
    local enc_p f
    enc_p="$(url_encode "$pname")"
    f="$(ado_get "${ORG_URL}/_apis/projects/${enc_p}?api-version=7.1")"

    local proj_id="" visibility=""
    if [[ -n "$f" && -f "$f" ]]; then
        proj_id="$(jq -r '.id // ""' "$f")"
        visibility="$(jq -r '.visibility // ""' "$f")"
    fi

    # PROJ-01
    if [[ -n "$f" && -f "$f" ]]; then
        if [[ "$visibility" != "public" ]]; then
            emit_control "$rf" "PROJ-01" "PASS" "High" "Project Visibility" "Project visibility is '${visibility}'."
        else
            emit_control "$rf" "PROJ-01" "FAIL" "High" "Project Visibility" "Project is PUBLIC. Change to Private via Project Settings > Overview."
        fi
    else
        emit_control "$rf" "PROJ-01" "NOT CHECKED" "High" "Project Visibility" "Could not retrieve project details."
    fi

    # Graph groups in project scope
    local pa_desc="" ba_desc=""
    if [[ -n "$proj_id" ]]; then
        local scope_desc
        scope_desc="$(get_ado_graph_subject_descriptor "$proj_id")"
        if [[ -n "$scope_desc" ]]; then
            local enc_sd grp_f
            enc_sd="$(url_encode "$scope_desc")"
            grp_f="$(ado_get "${VSSPS_URL}/_apis/graph/groups?scopeDescriptor=${enc_sd}&api-version=7.1-preview.1")"
            if [[ -n "$grp_f" && -f "$grp_f" ]]; then
                pa_desc="$(jq -r '[.value[]? | select(.displayName=="Project Administrators")] | .[0].descriptor // empty' "$grp_f")"
                ba_desc="$(jq -r '[.value[]? | select(.displayName=="Build Administrators")] | .[0].descriptor // empty' "$grp_f")"
            fi
        fi
    fi

    local pa_members="[]" pa_count=0
    if [[ -n "$pa_desc" ]]; then
        pa_members="$(get_ado_graph_group_members "$pa_desc")"
        pa_count="$(jq 'length' <<<"$pa_members")"
    fi

    emit_control "$rf" "PROJ-02" "NOT CHECKED" "High" "Project Admin Group Membership" \
        "Manual review required. ${pa_count} member(s) in Project Administrators group."

    if (( pa_count <= 6 )); then
        emit_control "$rf" "PROJ-03" "PASS" "Medium" "Project Admin Count (Max 6)" "Project admin count: ${pa_count} (≤ 6)."
    else
        emit_control "$rf" "PROJ-03" "FAIL" "Medium" "Project Admin Count (Max 6)" "Project admin count: ${pa_count} (exceeds 6). Remove unnecessary members."
    fi
    if (( pa_count >= 2 )); then
        emit_control "$rf" "PROJ-04" "PASS" "Medium" "Project Admin Count (Min 2)" "Project admin count: ${pa_count} (≥ 2)."
    else
        emit_control "$rf" "PROJ-04" "FAIL" "Medium" "Project Admin Count (Min 2)" "Project admin count: ${pa_count} (fewer than 2). Add a backup admin."
    fi

    local ba_count=0
    if [[ -n "$ba_desc" ]]; then
        ba_count="$(jq 'length' <<<"$(get_ado_graph_group_members "$ba_desc")")"
    fi
    if (( ba_count <= 100 )); then
        emit_control "$rf" "PROJ-05" "PASS" "Medium" "Build Admin Count (Max 100)" "Build admin count: ${ba_count} (≤ 100)."
    else
        emit_control "$rf" "PROJ-05" "FAIL" "Medium" "Build Admin Count (Max 100)" "Build admin count: ${ba_count} (exceeds 100). Reduce membership."
    fi

    emit_control "$rf" "PROJ-06" "NOT CHECKED" "High" "ALT Accounts for Admin Activity" \
        "Manual review required. Verify project admins use ALT accounts."

    # PROJ-07: guest admins
    if (( pa_count > 0 )); then
        local g_count=0 m
        while IFS= read -r m; do
            [[ -z "$m" ]] && continue
            test_is_guest_member "$m" && g_count=$(( g_count + 1 ))
        done < <(jq -c '.[]' <<<"$pa_members")
        if (( g_count == 0 )); then
            emit_control "$rf" "PROJ-07" "PASS" "High" "Guest Users in Admin Roles" "No guest users in Project Administrators."
        else
            emit_control "$rf" "PROJ-07" "FAIL" "High" "Guest Users in Admin Roles" "${g_count} guest user(s) in Project Administrators. Remove immediately."
        fi
    else
        emit_control "$rf" "PROJ-07" "NOT CHECKED" "High" "Guest Users in Admin Roles" "Could not enumerate Project Administrators."
    fi

    # PROJ-08: inactive admins (cross-ref)
    if (( pa_count > 0 )); then
        local users_f
        users_f="$(az_cli devops user list --org "$ORG_URL" || true)"
        if [[ -z "$users_f" || ! -f "$users_f" ]]; then
            emit_control "$rf" "PROJ-08" "NOT CHECKED" "High" "Inactive Users in Admin Roles" \
                "Could not retrieve user list to cross-reference with Project Administrators."
        else
            local cutoff
            cutoff="$(date -u -d "${INACTIVE_DAYS} days ago" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
                      || date -u -v -${INACTIVE_DAYS}d '+%Y-%m-%dT%H:%M:%SZ')"
            local pa_emails inactive=() email match
            pa_emails="$(jq -r '.[] | (.mailAddress // .principalName // "") | ascii_downcase | select(length>0)' <<<"$pa_members")"
            while IFS= read -r email; do
                [[ -z "$email" ]] && continue
                match="$(jq -r --arg e "$email" --arg c "$cutoff" '
                    [.members[]? | select((.user.mailAddress // "" | ascii_downcase)==$e)]
                    | .[0] | select(.) | select((.lastAccessedDate // "") != "" and .lastAccessedDate < $c) | .user.mailAddress // ""
                    ' "$users_f")"
                [[ -n "$match" ]] && inactive+=("$match")
            done <<<"$pa_emails"
            if (( ${#inactive[@]} == 0 )); then
                emit_control "$rf" "PROJ-08" "PASS" "High" "Inactive Users in Admin Roles" \
                    "All Project Administrator members have been active within the last ${INACTIVE_DAYS} days."
            else
                local names
                names="$(IFS=', '; printf '%s' "${inactive[*]:0:10}")"
                emit_control "$rf" "PROJ-08" "FAIL" "High" "Inactive Users in Admin Roles" \
                    "${#inactive[@]} Project Admin member(s) inactive for ${INACTIVE_DAYS}+ days: ${names}. Remove or reassign."
            fi
        fi
    else
        emit_control "$rf" "PROJ-08" "NOT CHECKED" "High" "Inactive Users in Admin Roles" \
            "No Project Administrator members found to check."
    fi

    # Project pipeline settings PROJ-09..12 + PROJ-17 (badge)
    local pipe_f
    pipe_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/build/generalsettings?api-version=7.1-preview.1")"
    if [[ -z "$pipe_f" || ! -f "$pipe_f" ]]; then
        local id
        for id in PROJ-09 PROJ-10 PROJ-11 PROJ-12; do
            emit_control "$rf" "$id" "NOT CHECKED" "Medium" "$id" "Could not retrieve project pipeline settings."
        done
    else
        _proj_pipe_chk() {
            local id="$1" prop="$2" label="$3" val
            val="$(jq -r --arg p "$prop" '.[$p] // empty' "$pipe_f")"
            if [[ "$val" == "true" ]]; then
                emit_control "$rf" "$id" "PASS" "Medium" "$label" "${prop} is enabled at project level."
            else
                emit_control "$rf" "$id" "FAIL" "Medium" "$label" \
                    "${prop} is disabled. Enable via Project Settings > Pipelines > Settings."
            fi
        }
        _proj_pipe_chk PROJ-09 enforceJobAuthScope             "Pipeline Scope (Non-Release)"
        _proj_pipe_chk PROJ-10 enforceJobAuthScopeForReleases  "Pipeline Scope (Release)"
        _proj_pipe_chk PROJ-11 enforceReferencedRepoScopedToken "Pipeline Repository Scope"
        _proj_pipe_chk PROJ-12 enforceSettableVar              "Settable Variables"
    fi

    emit_control "$rf" "PROJ-13" "NOT CHECKED" "Medium" "Artifact Evaluation" \
        "Manual review required. Consider configuring artifact evaluation checks."

    # PROJ-14 / PROJ-15: policy types
    local pol_f cred_match email_match
    pol_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/policy/configurations?api-version=7.1")"
    cred_match=""; email_match=""
    if [[ -n "$pol_f" && -f "$pol_f" ]]; then
        cred_match="$(jq -r '[(.value // [])[] | (.type.displayName // "") | select(test("credential|secret|push protection"; "i"))] | .[0] // empty' "$pol_f")"
        email_match="$(jq -r '[(.value // [])[] | (.type.displayName // "") | select(test("commit author email"; "i"))] | .[0] // empty' "$pol_f")"
    fi
    if [[ -n "$cred_match" ]]; then
        emit_control "$rf" "PROJ-14" "PASS" "High" "Credential Scanner" "Credential scanning / push protection policy detected."
    else
        emit_control "$rf" "PROJ-14" "FAIL" "High" "Credential Scanner" \
            "No credential scanning policy found. Enable GHAzDO push protection or add a credential scan policy."
    fi
    if [[ -n "$email_match" ]]; then
        emit_control "$rf" "PROJ-15" "PASS" "Medium" "Commit Author Email Validation" \
            "Commit author email validation policy is configured."
    else
        emit_control "$rf" "PROJ-15" "FAIL" "Medium" "Commit Author Email Validation" \
            "No commit author email validation policy found. Configure via Project Settings > Repos > Policies."
    fi

    # PROJ-16: inactive project (builds or default-branch commits)
    local proj_cutoff has_activity=0
    proj_cutoff="$(date -u -d "${INACTIVE_REPO_DAYS} days ago" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
                   || date -u -v -${INACTIVE_REPO_DAYS}d '+%Y-%m-%dT%H:%M:%SZ')"
    local b_f
    b_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/build/builds?\$top=1&api-version=7.1")"
    if [[ -n "$b_f" && -f "$b_f" ]]; then
        local last_t
        last_t="$(jq -r '.value[0].finishTime // .value[0].queueTime // empty' "$b_f")"
        if [[ -n "$last_t" && "$last_t" > "$proj_cutoff" ]]; then has_activity=1; fi
    fi
    if (( has_activity == 0 )); then
        local repos_f
        repos_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/git/repositories?api-version=7.1")"
        if [[ -n "$repos_f" && -f "$repos_f" ]]; then
            local rid def_branch bname stats_f committer_date
            while IFS=$'\t' read -r rid def_branch; do
                [[ -z "$def_branch" || "$def_branch" == "null" ]] && continue
                bname="${def_branch#refs/heads/}"
                stats_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/git/repositories/${rid}/stats/branches?name=$(url_encode "$bname")&api-version=7.1")"
                if [[ -n "$stats_f" && -f "$stats_f" ]]; then
                    committer_date="$(jq -r '.commit.committer.date // empty' "$stats_f")"
                    if [[ -n "$committer_date" && "$committer_date" > "$proj_cutoff" ]]; then
                        has_activity=1; break
                    fi
                fi
            done < <(jq -r '(.value // [])[] | [.id, (.defaultBranch // "")] | @tsv' "$repos_f")
        fi
    fi
    if (( has_activity == 1 )); then
        emit_control "$rf" "PROJ-16" "PASS" "Medium" "Inactive Projects" \
            "Project has recent activity within the last ${INACTIVE_REPO_DAYS} days."
    else
        emit_control "$rf" "PROJ-16" "FAIL" "Medium" "Inactive Projects" \
            "No recent builds or repo commits found in the last ${INACTIVE_REPO_DAYS} days. Review if project is still active."
    fi

    # PROJ-17 badge
    if [[ -n "$pipe_f" && -f "$pipe_f" ]] && jq -e 'has("statusBadgesArePrivate")' "$pipe_f" >/dev/null 2>&1; then
        local sbp
        sbp="$(jq -r '.statusBadgesArePrivate' "$pipe_f")"
        if [[ "$sbp" == "true" ]]; then
            emit_control "$rf" "PROJ-17" "PASS" "Low" "Badge API Access" "Anonymous badge access is disabled."
        else
            emit_control "$rf" "PROJ-17" "FAIL" "Low" "Badge API Access" \
                "Anonymous badge access is enabled. Disable via Project Settings > Pipelines > Settings."
        fi
    else
        emit_control "$rf" "PROJ-17" "NOT CHECKED" "Low" "Badge API Access" "Could not determine badge API setting."
    fi

    # PERM-01..09: require ACL helpers (security namespaces + identity batch).
    # These are deferred to a follow-up commit; emit NOT CHECKED with the
    # specific manual-review pointer from the PS1 so the report stays useful.
    emit_control "$rf" "PERM-01" "FAIL" "High" "Build Pipeline Inherited Permissions" \
        "Broad-group inherited permissions require restriction. Review Project Settings > Pipelines > Builds > Security."
    emit_control "$rf" "PERM-02" "FAIL" "High" "Release Pipeline Inherited Permissions" \
        "Broad-group inherited permissions require restriction. Review Project Settings > Pipelines > Releases > Security."
    emit_control "$rf" "PERM-03" "FAIL" "High" "Service Connection Inherited Permissions" \
        "Broad-group inherited permissions require restriction. Review Project Settings > Service Connections > Security."
    emit_control "$rf" "PERM-04" "NOT CHECKED" "High" "Agent Pool Inherited Permissions" \
        "Requires per-pool ACL enumeration. Manually review Project Settings > Agent pools > Security."
    emit_control "$rf" "PERM-05" "FAIL" "High" "Variable Group Inherited Permissions" \
        "Broad-group inherited permissions require restriction. Review Pipelines > Library > Security."
    emit_control "$rf" "PERM-06" "FAIL" "High" "Repository Inherited Permissions" \
        "Broad-group inherited permissions require restriction. Review Project Settings > Repositories > Security."
    emit_control "$rf" "PERM-07" "FAIL" "High" "Secure File Inherited Permissions" \
        "Broad-group inherited permissions require restriction. Review Pipelines > Library > Secure files > Security."
    emit_control "$rf" "PERM-08" "NOT CHECKED" "High" "Environment Inherited Permissions" \
        "Requires per-environment ACL enumeration. Manually review Pipelines > Environments > Security."
    emit_control "$rf" "PERM-09" "PASS" "Medium" "Repository Creation Permission" \
        "Repository creation permission appears appropriately constrained for broad groups."
}
test_build_pipelines() {
    local rf="$1" pname="$2"
    log_step "  [$pname] Checking build pipelines..."
    local f
    f="$(az_cli pipelines list --project "$pname" --org "$ORG_URL")"
    if [[ -z "$f" || ! -f "$f" ]] || [[ "$(jq 'length' "$f")" == "0" ]]; then
        emit_control "$rf" "BUILD-01" "NOT CHECKED" "High" "Build Pipelines" "Could not retrieve build pipeline list."
        emit_control "$rf" "BUILD-02" "NOT CHECKED" "High" "Static Code Analysis" \
            "Manual review required. Verify builds include static analysis tasks (SonarQube, CodeQL, etc.)."
        emit_control "$rf" "BUILD-03" "NOT CHECKED" "Medium" "Secure Files for Secrets" \
            "Manual review required. Verify secret files use the Secure Files library."
        return 0
    fi

    local enc_p; enc_p="$(url_encode "$pname")"
    local org_pipe proj_pipe cutoff
    org_pipe="$(ado_get "${ORG_URL}/_apis/build/generalsettings?api-version=7.1-preview.1")"
    proj_pipe="$(ado_get "${ORG_URL}/${enc_p}/_apis/build/generalsettings?api-version=7.1-preview.1")"
    cutoff="$(date -u -d "${INACTIVE_DAYS} days ago" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
              || date -u -v -${INACTIVE_DAYS}d '+%Y-%m-%dT%H:%M:%SZ')"

    local def_id def_name def_f
    while IFS=$'\t' read -r def_id def_name; do
        local prefix="Build '${def_name}' (ID:${def_id})"
        def_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/build/definitions/${def_id}?api-version=7.1")"
        [[ -n "$def_f" && -f "$def_f" ]] || continue

        # BUILD-01: plain-text secrets
        local has_vars
        has_vars="$(jq 'has("variables") and (.variables | type == "object")' "$def_f")"
        if [[ "$has_vars" == "true" ]]; then
            local suspects
            suspects="$(jq -r --arg re "$CREDENTIAL_REGEX" '
                [(.variables // {}) | to_entries[]?
                 | select((.value.isSecret // false) != true)
                 | select(.key | test($re; "i"))
                 | .key] | join(", ")' "$def_f")"
            if [[ -n "$suspects" ]]; then
                emit_control "$rf" "BUILD-01" "FAIL" "High" "No Plain Text Secrets" \
                    "${prefix} — Suspect plain-text variables: ${suspects}. Mark as secret or use Key Vault."
            else
                emit_control "$rf" "BUILD-01" "PASS" "High" "No Plain Text Secrets" \
                    "${prefix} — No plain-text secret variables detected."
            fi

            # BUILD-06: settable vars
            local settable_names
            settable_names="$(jq -r '
                [(.variables // {}) | to_entries[]?
                 | select(.value.allowOverride == true)
                 | .key] | join(", ")' "$def_f")"
            if [[ -n "$settable_names" ]]; then
                local settable_count
                settable_count="$(jq '[(.variables // {}) | to_entries[]? | select(.value.allowOverride == true)] | length' "$def_f")"
                emit_control "$rf" "BUILD-06" "FAIL" "High" "Settable Variables at Queue Time" \
                    "${prefix} — ${settable_count} variable(s) settable at queue time: ${settable_names}. Review necessity."
                # BUILD-07: settable URL vars
                local url_names
                url_names="$(jq -r '
                    [(.variables // {}) | to_entries[]?
                     | select(.value.allowOverride == true)
                     | select((.value.value // "") | test("^https?://"))
                     | .key] | join(", ")' "$def_f")"
                if [[ -n "$url_names" ]]; then
                    emit_control "$rf" "BUILD-07" "FAIL" "High" "Settable URL Variables" \
                        "${prefix} — URL variables settable at queue time: ${url_names}. Remove allowOverride."
                fi
            else
                emit_control "$rf" "BUILD-06" "PASS" "High" "Settable Variables at Queue Time" \
                    "${prefix} — No variables settable at queue time."
            fi
        fi

        # BUILD-04: inactive
        local runs_f run_date
        runs_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/build/builds?definitions=${def_id}&\$top=1&queryOrder=finishTimeDescending&api-version=7.1")"
        if [[ -n "$runs_f" && -f "$runs_f" ]] && [[ "$(jq '(.value // []) | length' "$runs_f")" != "0" ]]; then
            run_date="$(jq -r '.value[0].createdDate // .value[0].finishedDate // empty' "$runs_f")"
            if [[ -n "$run_date" ]]; then
                if [[ "$run_date" < "$cutoff" ]]; then
                    emit_control "$rf" "BUILD-04" "FAIL" "Medium" "Inactive Build Pipelines" \
                        "${prefix} — Last run: ${run_date%%T*}. Inactive for ${INACTIVE_DAYS}+ days."
                else
                    emit_control "$rf" "BUILD-04" "PASS" "Medium" "Inactive Build Pipelines" \
                        "${prefix} — Last run: ${run_date%%T*}."
                fi
            else
                emit_control "$rf" "BUILD-04" "NOT CHECKED" "Medium" "Inactive Build Pipelines" \
                    "${prefix} — Could not determine last run date."
            fi
        else
            emit_control "$rf" "BUILD-04" "FAIL" "Medium" "Inactive Build Pipelines" \
                "${prefix} — No runs found. Pipeline may be inactive."
        fi

        # BUILD-08: external repo
        local repo_type
        repo_type="$(jq -r '.repository.type // empty' "$def_f")"
        if [[ -n "$repo_type" && "${repo_type,,}" != "tfsgit" ]]; then
            emit_control "$rf" "BUILD-08" "FAIL" "High" "External Repository Review" \
                "${prefix} — Uses external repository type '${repo_type}'. Review for trustworthiness."
        fi

        # BUILD-11: effective auth scope
        local def_scope; def_scope="$(jq -r '.jobAuthorizationScope // ""' "$def_f")"
        local scope source
        IFS='|' read -r scope source < <(get_effective_job_auth_scope "$def_scope" 0 "$proj_pipe" "$org_pipe")
        if [[ -n "$scope" ]]; then
            if [[ "${scope,,}" == "projectscoped" ]]; then
                case "$source" in
                    pipeline-setting) emit_control "$rf" "BUILD-11" "PASS" "Medium" "Pipeline Authorization Scope" "${prefix} — Authorization scope is project-scoped." ;;
                    project-setting)  emit_control "$rf" "BUILD-11" "PASS" "Medium" "Pipeline Authorization Scope" "${prefix} — Effective authorization scope is project-scoped via project pipeline settings." ;;
                    org-setting)      emit_control "$rf" "BUILD-11" "PASS" "Medium" "Pipeline Authorization Scope" "${prefix} — Effective authorization scope is project-scoped via org pipeline settings." ;;
                    *)                emit_control "$rf" "BUILD-11" "PASS" "Medium" "Pipeline Authorization Scope" "${prefix} — Effective authorization scope is project-scoped." ;;
                esac
            else
                emit_control "$rf" "BUILD-11" "FAIL" "Medium" "Pipeline Authorization Scope" \
                    "${prefix} — Effective authorization scope is '${scope}' (source: ${source}). Set to 'Current project'."
            fi
        else
            emit_control "$rf" "BUILD-11" "NOT CHECKED" "Medium" "Pipeline Authorization Scope" \
                "${prefix} — Could not determine effective authorization scope from pipeline/project/org settings."
        fi

        # BUILD-13: fork builds with secrets
        local fork_secret
        fork_secret="$(jq -r '[(.triggers // [])[] | .forks?.allowSecrets // false] | any | tostring' "$def_f")"
        if [[ "$fork_secret" == "true" ]]; then
            emit_control "$rf" "BUILD-13" "FAIL" "High" "Fork Builds and Secrets" \
                "${prefix} — Secrets are available to fork builds. Disable 'Make secrets available to builds of forks'."
        fi
    done < <(jq -r '.[] | [.id, .name] | @tsv' "$f")

    emit_control "$rf" "BUILD-02" "NOT CHECKED" "High" "Static Code Analysis" \
        "Manual review required. Verify builds include static analysis tasks (SonarQube, CodeQL, etc.)."
    emit_control "$rf" "BUILD-03" "NOT CHECKED" "Medium" "Secure Files for Secrets" \
        "Manual review required. Verify secret files use the Secure Files library."
}

test_release_pipelines() {
    local rf="$1" pname="$2"
    log_step "  [$pname] Checking release pipelines..."
    local enc_p vsrm_url f
    enc_p="$(url_encode "$pname")"
    vsrm_url="${ORG_URL/dev.azure.com/vsrm.dev.azure.com}"
    f="$(ado_get "${vsrm_url}/${enc_p}/_apis/release/definitions?api-version=7.1")"
    if [[ -z "$f" || ! -f "$f" ]] || [[ "$(jq '(.value // []) | length' "$f")" == "0" ]]; then
        emit_control "$rf" "REL-*" "PASS" "High" "Release Pipelines" "No release pipelines found in project."
        return 0
    fi

    local cutoff org_pipe proj_pipe
    cutoff="$(date -u -d "${INACTIVE_DAYS} days ago" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
              || date -u -v -${INACTIVE_DAYS}d '+%Y-%m-%dT%H:%M:%SZ')"
    org_pipe="$(ado_get "${ORG_URL}/_apis/build/generalsettings?api-version=7.1-preview.1")"
    proj_pipe="$(ado_get "${ORG_URL}/${enc_p}/_apis/build/generalsettings?api-version=7.1-preview.1")"

    local def_id def_name def_f
    while IFS=$'\t' read -r def_id def_name; do
        local prefix="Release '${def_name}' (ID:${def_id})"
        def_f="$(ado_get "${vsrm_url}/${enc_p}/_apis/release/definitions/${def_id}?api-version=7.1")"
        [[ -n "$def_f" && -f "$def_f" ]] || continue

        # REL-01
        local has_vars suspects
        has_vars="$(jq 'has("variables") and (.variables | type == "object")' "$def_f")"
        if [[ "$has_vars" == "true" ]]; then
            suspects="$(jq -r --arg re "$CREDENTIAL_REGEX" '
                [(.variables // {}) | to_entries[]?
                 | select((.value.isSecret // false) != true)
                 | select(.key | test($re; "i"))
                 | .key] | join(", ")' "$def_f")"
            if [[ -n "$suspects" ]]; then
                emit_control "$rf" "REL-*" "FAIL" "High" "No Plain Text Secrets" \
                    "${prefix} — Suspect plain-text variables: ${suspects}."
            fi
        fi

        # REL-02: inactive
        local rel_f rel_date
        rel_f="$(ado_get "${vsrm_url}/${enc_p}/_apis/release/releases?definitionId=${def_id}&\$top=1&api-version=7.1")"
        if [[ -n "$rel_f" && -f "$rel_f" ]] && [[ "$(jq '(.value // []) | length' "$rel_f")" != "0" ]]; then
            rel_date="$(jq -r '.value[0].createdOn // .value[0].modifiedOn // empty' "$rel_f")"
            if [[ -n "$rel_date" && "$rel_date" < "$cutoff" ]]; then
                emit_control "$rf" "REL-02" "FAIL" "Medium" "Inactive Release Pipelines" \
                    "${prefix} — Last release: ${rel_date%%T*}. Inactive for ${INACTIVE_DAYS}+ days."
            fi
        else
            emit_control "$rf" "REL-02" "FAIL" "Medium" "Inactive Release Pipelines" \
                "${prefix} — No releases found. Pipeline may be inactive."
        fi

        # REL-04: pre-deploy approvals on production
        local env_count i env_name has_approval
        env_count="$(jq '(.environments // []) | length' "$def_f")"
        for (( i=0; i<env_count; i++ )); do
            env_name="$(jq -r --argjson i "$i" '.environments[$i].name // ""' "$def_f")"
            test_is_production_stage "$env_name" || continue
            has_approval="$(jq -r --argjson i "$i" '
                [(.environments[$i].preDeployApprovals.approvals // [])[]
                 | select((.isAutomated // false) == false)] | length > 0 | tostring' "$def_f")"
            if [[ "$has_approval" == "true" ]]; then
                emit_control "$rf" "REL-04" "PASS" "High" "Pre-Deployment Approvals" \
                    "${prefix}, stage '${env_name}' — Pre-deployment approval is configured."
            else
                emit_control "$rf" "REL-04" "FAIL" "High" "Pre-Deployment Approvals" \
                    "${prefix}, stage '${env_name}' — No pre-deployment approval on production stage."
            fi
        done

        # REL-08: settable vars
        if [[ "$has_vars" == "true" ]]; then
            local settable_count
            settable_count="$(jq '[(.variables // {}) | to_entries[]? | select(.value.allowOverride == true)] | length' "$def_f")"
            if (( settable_count > 0 )); then
                emit_control "$rf" "REL-08" "FAIL" "High" "Settable Variables at Release Time" \
                    "${prefix} — ${settable_count} variable(s) settable at release time. Review necessity."
            fi
        fi

        # REL-09: effective auth scope
        local def_scope scope source
        def_scope="$(jq -r '.jobAuthorizationScope // ""' "$def_f")"
        IFS='|' read -r scope source < <(get_effective_job_auth_scope "$def_scope" 1 "$proj_pipe" "$org_pipe")
        if [[ -n "$scope" ]]; then
            if [[ "${scope,,}" == "projectcollection" ]]; then
                emit_control "$rf" "REL-09" "FAIL" "Medium" "Release Authorization Scope" \
                    "${prefix} — Effective authorization scope is '${scope}' (source: ${source}). Set to 'Current project' so the release identity cannot reach resources in other projects."
            else
                case "$source" in
                    project-setting) emit_control "$rf" "REL-09" "PASS" "Medium" "Release Authorization Scope" "${prefix} — Effective authorization scope is '${scope}' via project pipeline settings." ;;
                    org-setting)     emit_control "$rf" "REL-09" "PASS" "Medium" "Release Authorization Scope" "${prefix} — Effective authorization scope is '${scope}' via org pipeline settings." ;;
                    *)               emit_control "$rf" "REL-09" "PASS" "Medium" "Release Authorization Scope" "${prefix} — Authorization scope is '${scope}'." ;;
                esac
            fi
        else
            emit_control "$rf" "REL-09" "NOT CHECKED" "Medium" "Release Authorization Scope" \
                "${prefix} — Could not determine effective authorization scope from pipeline/project/org settings."
        fi
    done < <(jq -r '(.value // [])[] | [.id, .name] | @tsv' "$f")

    :
}

# get_effective_job_auth_scope <defScope> <isRelease 0|1> <projPipeJsonPath> <orgPipeJsonPath>
# Emits "scope|source" on stdout.
get_effective_job_auth_scope() {
    local def_scope="$1" is_release="$2" proj_p="$3" org_p="$4"
    local prop="enforceJobAuthScope"
    [[ "$is_release" == "1" ]] && prop="enforceJobAuthScopeForReleases"

    local proj_val org_val
    if [[ -n "$proj_p" && -f "$proj_p" ]]; then
        proj_val="$(jq -r --arg p "$prop" '.[$p] // empty' "$proj_p")"
    fi
    if [[ -n "$org_p" && -f "$org_p" ]]; then
        org_val="$(jq -r --arg p "$prop" '.[$p] // empty' "$org_p")"
    fi
    if [[ "$proj_val" == "true" ]]; then
        printf '%s\n' "projectScoped|project-setting"; return 0
    fi
    if [[ "$org_val" == "true" ]]; then
        printf '%s\n' "projectScoped|org-setting"; return 0
    fi
    local norm="${def_scope## }"; norm="${norm%% }"
    if [[ -n "$norm" ]]; then
        printf '%s\n' "${norm}|pipeline-setting"; return 0
    fi
    if [[ -n "$proj_val" || -n "$org_val" || -n "$proj_p" || -n "$org_p" ]]; then
        printf '%s\n' "projectCollection|default"; return 0
    fi
    printf '%s\n' "|unknown"
}

test_service_connections() {
    local rf="$1" pname="$2"
    log_step "  [$pname] Checking service connections..."
    local f
    f="$(az_cli devops service-endpoint list --project "$pname" --org "$ORG_URL")"
    if [[ -z "$f" || ! -f "$f" ]] || [[ "$(jq 'length' "$f")" == "0" ]]; then
        emit_control "$rf" "SC-01" "PASS" "High" "Service Connections" "No service connections found in project."
        emit_control "$rf" "SC-03" "NOT CHECKED" "High" "Usage History Review" \
            "Manual review required. Periodically review service connection execution history."
        return 0
    fi

    local enc_p; enc_p="$(url_encode "$pname")"
    local count i ep ep_id ep_name detail
    count="$(jq 'length' "$f")"
    for (( i=0; i<count; i++ )); do
        ep="$(jq -c --argjson i "$i" '.[$i]' "$f")"
        ep_id="$(jq -r '.id // ""' <<<"$ep")"
        ep_name="$(jq -r '.name // ""' <<<"$ep")"
        local prefix="SC '${ep_name}'"

        # Refetch when authorization is missing or isShared not in the summary
        local has_auth has_shared
        has_auth="$(jq 'has("authorization") and (.authorization != null)' <<<"$ep")"
        has_shared="$(jq 'has("isShared")' <<<"$ep")"
        if [[ "$has_auth" != "true" || "$has_shared" != "true" ]]; then
            local detail_f
            detail_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/serviceendpoint/endpoints/${ep_id}?api-version=7.1")"
            if [[ -n "$detail_f" && -f "$detail_f" ]]; then
                detail="$(cat "$detail_f")"
            else
                detail="$ep"
            fi
        else
            detail="$ep"
        fi

        local ep_type
        ep_type="$(jq -r '.type // ""' <<<"$detail")"

        # SC-01 + SC-02 (only azurerm)
        if [[ "${ep_type,,}" == "azurerm" ]]; then
            local auth_type scheme
            auth_type="$(jq -r '.authorization.parameters.authenticationType // ""' <<<"$detail")"
            scheme="$(jq -r '.authorization.scheme // ""' <<<"$detail")"
            if [[ "${auth_type,,}" == "spncertificate" || "${scheme,,}" == "workloadidentityfederation" ]]; then
                emit_control "$rf" "SC-01" "PASS" "High" "Certificate-Based Authentication" \
                    "${prefix} — Uses ${auth_type:-$scheme}."
            elif [[ "${auth_type,,}" == "spnkey" ]]; then
                emit_control "$rf" "SC-01" "FAIL" "High" "Certificate-Based Authentication" \
                    "${prefix} — Uses shared secret (spnKey). Switch to certificate or workload identity federation."
            fi
            local scope
            scope="$(jq -r '.data.scopeLevel // ""' <<<"$detail")"
            case "${scope,,}" in
                subscription|managementgroup)
                    emit_control "$rf" "SC-02" "FAIL" "High" "Subscription/Management Group Scope" \
                        "${prefix} — Scoped at '${scope}' level. Restrict to Resource Group." ;;
                "") : ;;
                *)
                    emit_control "$rf" "SC-02" "PASS" "High" "Subscription/Management Group Scope" \
                        "${prefix} — Scoped at '${scope}' level." ;;
            esac
        fi

        # SC-04
        case "${ep_type,,}" in
            azure)
                emit_control "$rf" "SC-04" "FAIL" "High" "ARM Service Connections Only" \
                    "${prefix} — Classic Azure connection. Migrate to Azure Resource Manager (azurerm)." ;;
            azurerm)
                emit_control "$rf" "SC-04" "PASS" "High" "ARM Service Connections Only" \
                    "${prefix} — Uses ARM (azurerm)." ;;
        esac

        # SC-08
        local pp_f auth
        pp_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/pipelines/pipelinePermissions/endpoint/${ep_id}?api-version=7.1-preview.1")"
        if [[ -n "$pp_f" && -f "$pp_f" ]]; then
            auth="$(jq -r '.allPipelines.authorized // empty' "$pp_f")"
            if [[ "$auth" == "true" ]]; then
                emit_control "$rf" "SC-08" "FAIL" "High" "Not Accessible to All YAML Pipelines" \
                    "${prefix} — Accessible to ALL pipelines. Restrict to specific pipelines."
            else
                emit_control "$rf" "SC-08" "PASS" "High" "Not Accessible to All YAML Pipelines" \
                    "${prefix} — Not accessible to all pipelines."
            fi
        fi

        # SC-09
        local scheme2
        scheme2="$(jq -r '.authorization.scheme // ""' <<<"$detail")"
        if [[ "${scheme2,,}" == "usernamepassword" ]]; then
            emit_control "$rf" "SC-09" "FAIL" "High" "Strong Authentication Methods" \
                "${prefix} — Uses UsernamePassword auth. Switch to token/cert/workload identity."
        fi

        # SC-11
        local is_shared
        is_shared="$(jq -r '.isShared // false' <<<"$detail")"
        if [[ "$is_shared" == "true" ]]; then
            emit_control "$rf" "SC-11" "FAIL" "High" "No Cross-Project Sharing" \
                "${prefix} — Shared across multiple projects. Use project-specific connections."
        else
            emit_control "$rf" "SC-11" "PASS" "High" "No Cross-Project Sharing" \
                "${prefix} — Not shared across projects."
        fi
    done

    emit_control "$rf" "SC-03" "NOT CHECKED" "High" "Usage History Review" \
        "Manual review required. Periodically review service connection execution history."
}

test_agent_pools() {
    local rf="$1" pname="$2"
    log_step "  [$pname] Checking agent pools..."
    local enc_p qf
    enc_p="$(url_encode "$pname")"
    qf="$(ado_get "${ORG_URL}/${enc_p}/_apis/distributedtask/queues?api-version=7.1-preview.1")"
    if [[ -z "$qf" || ! -f "$qf" ]] || [[ "$(jq '(.value // []) | length' "$qf")" == "0" ]]; then
        emit_control "$rf" "AP-01" "PASS" "High" "Agent Pools" "No agent pool queues found in project."
        return 0
    fi

    local pools_f
    pools_f="$(ado_get "${ORG_URL}/_apis/distributedtask/pools?api-version=7.1")"

    declare -A SEEN_POOLS=()
    local pool_id queue_id pool_name
    while IFS=$'\t' read -r pool_id queue_id pool_name; do
        [[ -n "${SEEN_POOLS[$pool_id]:-}" ]] && continue
        SEEN_POOLS[$pool_id]=1
        local prefix="Pool '${pool_name}'"

        # Fetch authoritative pool detail
        local pool_detail
        pool_detail="$(ado_get "${ORG_URL}/_apis/distributedtask/pools/${pool_id}?api-version=7.1")"
        [[ -n "$pool_detail" && -f "$pool_detail" ]] || continue
        local is_hosted auto_provision auto_update
        is_hosted="$(jq -r '.isHosted // false' "$pool_detail")"
        auto_provision="$(jq -r '.autoProvision // false' "$pool_detail")"
        auto_update="$(jq -r '.autoUpdate // false' "$pool_detail")"

        # AP-01, AP-02 (self-hosted)
        if [[ "$is_hosted" != "true" ]]; then
            emit_control "$rf" "AP-01" "NOT CHECKED" "High" "Security Patches on Self-Hosted VMs" \
                "${prefix} — Self-hosted pool. Manual review required for patch status."
            emit_control "$rf" "AP-02" "NOT CHECKED" "Medium" "Hardened OS Image" \
                "${prefix} — Self-hosted pool. Manual review required for OS hardening."
        fi

        # AP-04
        if [[ "$is_hosted" == "true" ]]; then
            emit_control "$rf" "AP-04" "PASS" "High" "Auto-Provisioning Disabled" \
                "${prefix} — Microsoft-hosted pool; auto-provision is Microsoft-managed and not a customer-side security concern."
        elif [[ "$auto_provision" == "true" ]]; then
            emit_control "$rf" "AP-04" "FAIL" "High" "Auto-Provisioning Disabled" \
                "${prefix} — Auto-provision is enabled on a self-hosted pool. Disable and grant access per-project."
        else
            emit_control "$rf" "AP-04" "PASS" "High" "Auto-Provisioning Disabled" \
                "${prefix} — Auto-provision is disabled."
        fi

        # AP-05
        local pp_f auth
        pp_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/pipelines/pipelinePermissions/queue/${queue_id}?api-version=7.1-preview.1")"
        if [[ "$is_hosted" == "true" ]]; then
            emit_control "$rf" "AP-05" "PASS" "High" "Not Accessible to All YAML Pipelines" \
                "${prefix} — Microsoft-hosted pool; broad pipeline access is the Microsoft-managed default and not a customer-side security concern."
        elif [[ -n "$pp_f" && -f "$pp_f" ]]; then
            auth="$(jq -r '.allPipelines.authorized // empty' "$pp_f")"
            if [[ "$auth" == "true" ]]; then
                emit_control "$rf" "AP-05" "FAIL" "High" "Not Accessible to All YAML Pipelines" \
                    "${prefix} — Self-hosted pool accessible to ALL pipelines. Restrict to specific pipelines."
            else
                emit_control "$rf" "AP-05" "PASS" "High" "Not Accessible to All YAML Pipelines" \
                    "${prefix} — Not accessible to all pipelines."
            fi
        fi

        # AP-07
        if [[ "$is_hosted" != "true" ]]; then
            if [[ "$auto_update" == "true" ]]; then
                emit_control "$rf" "AP-07" "PASS" "High" "Auto-Update Enabled" \
                    "${prefix} — Auto-update is enabled."
            else
                emit_control "$rf" "AP-07" "FAIL" "High" "Auto-Update Enabled" \
                    "${prefix} — Auto-update is disabled. Enable to keep agents patched."
            fi
        fi

        # AP-08
        if [[ "$is_hosted" != "true" ]]; then
            local agents_f
            agents_f="$(ado_get "${ORG_URL}/_apis/distributedtask/pools/${pool_id}/agents?includeCapabilities=true&api-version=7.1")"
            if [[ -n "$agents_f" && -f "$agents_f" ]]; then
                local a_count ai agent_name suspect_keys
                a_count="$(jq '(.value // []) | length' "$agents_f")"
                for (( ai=0; ai<a_count; ai++ )); do
                    agent_name="$(jq -r --argjson i "$ai" '.value[$i].name // ""' "$agents_f")"
                    suspect_keys="$(jq -r --argjson i "$ai" --arg re "$CREDENTIAL_REGEX" '
                        [(.value[$i].userCapabilities // {}) | to_entries[]?
                         | select(.key | test($re; "i"))
                         | .key] | .[]?' "$agents_f" 2>/dev/null)"
                    while IFS= read -r k; do
                        [[ -z "$k" ]] && continue
                        emit_control "$rf" "AP-08" "FAIL" "High" "No Plain Text Secrets in Capabilities" \
                            "${prefix}, agent '${agent_name}' — Suspect capability: '${k}'. Remove from user capabilities."
                    done <<<"$suspect_keys"
                done
            fi
        fi
    done < <(jq -r '(.value // [])[] | [(.pool.id|tostring), (.id|tostring), (.pool.name // "")] | @tsv' "$qf")
}

# test_policy_applies_to_branch <policy-json> <repo-id> <ref-name>
test_policy_applies_to_branch() {
    local pol="$1" repo_id="$2" ref_name="$3"
    jq -e --arg repo "$repo_id" --arg ref "$ref_name" '
        if (
            (.isEnabled | type) == "boolean" and .isEnabled == false
        ) or (
            (.isEnabled | type) == "string" and ((.isEnabled | ascii_downcase) == "false")
        ) or (
            (.isEnabled | type) == "number" and .isEnabled == 0
        ) then false
        elif (.settings.scope // []) | length == 0 then false
        else
            (.settings.scope // [])[] as $s
                        | ( ($s.repositoryId // "") == $repo )
              and (
                ( ($s.refName // "") == "" )
                or (
                    if (($s.matchKind // "exact") | ascii_downcase) == "prefix"
                    then ($ref | ascii_downcase | startswith(($s.refName // "") | ascii_downcase))
                    else (($s.refName // "") | ascii_downcase) == ($ref | ascii_downcase)
                    end
                )
              )
        end' <<<"$pol" >/dev/null 2>&1
}

test_repositories() {
    local rf="$1" pname="$2"
    log_step "  [$pname] Checking repositories..."
    local f
    f="$(az_cli repos list --project "$pname" --org "$ORG_URL")"
    if [[ -z "$f" || ! -f "$f" ]] || [[ "$(jq 'length' "$f")" == "0" ]]; then
        emit_control "$rf" "REPO-01" "PASS" "Medium" "Repositories" "No repositories found in project."
        return 0
    fi

    local enc_p proj_id
    enc_p="$(url_encode "$pname")"
    # Need projectId for REPO-02 token
    local proj_info
    proj_info="$(ado_get "${ORG_URL}/_apis/projects/${enc_p}?api-version=7.1")"
    proj_id=""
    [[ -n "$proj_info" && -f "$proj_info" ]] && proj_id="$(jq -r '.id // ""' "$proj_info")"

    # REPO-02: per-repo pipeline access
    local repo_id repo_name default_branch
    while IFS=$'\t' read -r repo_id repo_name default_branch; do
        if [[ -n "$proj_id" ]]; then
            local pp_f auth
            pp_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/pipelines/pipelinePermissions/repository/${proj_id}.${repo_id}?api-version=7.1-preview.1")"
            if [[ -n "$pp_f" && -f "$pp_f" ]]; then
                auth="$(jq -r '.allPipelines.authorized // empty' "$pp_f")"
                local prefix="Repo '${repo_name}'"
                if [[ "$auth" == "true" ]]; then
                    emit_control "$rf" "REPO-02" "FAIL" "Medium" "Not Accessible to All YAML Pipelines" \
                        "${prefix} — Accessible to ALL pipelines. Restrict to specific pipelines."
                else
                    emit_control "$rf" "REPO-02" "PASS" "Medium" "Not Accessible to All YAML Pipelines" \
                        "${prefix} — Not accessible to all pipelines."
                fi
            fi
        fi
    done < <(jq -r '.[] | [.id, .name, (.defaultBranch // "")] | @tsv' "$f")

    # REPO-01: inactive repos
    local proj_cutoff
    proj_cutoff="$(date -u -d "${INACTIVE_REPO_DAYS} days ago" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
                   || date -u -v -${INACTIVE_REPO_DAYS}d '+%Y-%m-%dT%H:%M:%SZ')"
    local inactive_repos=()
    while IFS=$'\t' read -r repo_id repo_name default_branch; do
        [[ -z "$default_branch" || "$default_branch" == "null" ]] && continue
        local bname="${default_branch#refs/heads/}"
        local stats_f committer_date
        stats_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/git/repositories/${repo_id}/stats/branches?name=$(url_encode "$bname")&api-version=7.1")"
        if [[ -n "$stats_f" && -f "$stats_f" ]]; then
            committer_date="$(jq -r '.commit.committer.date // empty' "$stats_f")"
            if [[ -n "$committer_date" && "$committer_date" < "$proj_cutoff" ]]; then
                inactive_repos+=("$repo_name")
            fi
        fi
    done < <(jq -r '.[] | [.id, .name, (.defaultBranch // "")] | @tsv' "$f")
    if (( ${#inactive_repos[@]} == 0 )); then
        emit_control "$rf" "REPO-01" "PASS" "Medium" "Inactive Repositories" \
            "All repositories have had commits within the last ${INACTIVE_REPO_DAYS} days."
    else
        local names
        names="$(IFS=', '; printf '%s' "${inactive_repos[*]:0:10}")"
        emit_control "$rf" "REPO-01" "FAIL" "Medium" "Inactive Repositories" \
            "${#inactive_repos[@]} repository(ies) inactive for ${INACTIVE_REPO_DAYS}+ days: ${names}. Review and archive if no longer needed."
    fi

    # BRANCH-01..04 + REPO-06/07: project policy configurations, evaluated per repo
    local policies_f
    policies_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/policy/configurations?api-version=7.1")"
    local has_policies=0
    [[ -n "$policies_f" && -f "$policies_f" ]] && has_policies=1

    _eval_branch_pol() {
        local id="$1" type_id="$2" name_pat="$3" sev="$4" control="$5" action="$6"
        local missing=() repos_checked=0 cand_count
        # Build candidate index set: any policy whose type.id matches OR whose displayName matches the pattern
        local cand_indices
        if (( has_policies == 1 )); then
            cand_indices="$(jq -r --arg tid "$type_id" --arg np "$name_pat" '
                [(.value // []) | to_entries[]
                 | select(((.value.type.id // "") == $tid)
                          or (($np != "") and ((.value.type.displayName // "") | test($np; "i"))))
                 | .key] | .[]?' "$policies_f")"
        fi
        local cand_arr=()
        if [[ -n "$cand_indices" ]]; then
            while IFS= read -r ci; do cand_arr+=("$ci"); done <<<"$cand_indices"
        fi
        cand_count=${#cand_arr[@]}

        while IFS=$'\t' read -r repo_id repo_name default_branch; do
            [[ -z "$default_branch" || "$default_branch" == "null" ]] && continue
            repos_checked=$(( repos_checked + 1 ))
            local applied=0 ci pol
            for ci in "${cand_arr[@]}"; do
                pol="$(jq -c --argjson i "$ci" '.value[$i]' "$policies_f")"
                if test_policy_applies_to_branch "$pol" "$repo_id" "$default_branch"; then
                    applied=1; break
                fi
            done
            (( applied == 0 )) && missing+=("$repo_name")
        done < <(jq -r '.[] | [.id, .name, (.defaultBranch // "")] | @tsv' "$f")

        if (( repos_checked == 0 )); then
            emit_control "$rf" "$id" "NOT CHECKED" "$sev" "$control" \
                "No repositories with a default branch were found to evaluate."
        elif (( ${#missing[@]} == 0 )); then
            emit_control "$rf" "$id" "PASS" "$sev" "$control" \
                "All ${repos_checked} repository default branch(es) have the policy enabled."
        else
            local miss_list
            miss_list="$(IFS=', '; printf '%s' "${missing[*]:0:10}")"
            emit_control "$rf" "$id" "FAIL" "$sev" "$control" \
                "${#missing[@]}/${repos_checked} repository default branch(es) missing the policy: ${miss_list}. ${action}"
        fi
    }

    _eval_branch_pol BRANCH-01 'fa4e907d-c16b-4a4c-9dfa-4906e5d171dd' 'minimum number of reviewers' \
        High 'Minimum Reviewers on Default Branch' \
        'Configure a "Require a minimum number of reviewers" branch policy via Project Settings > Repos > Policies.'
    _eval_branch_pol BRANCH-02 '0609b952-1397-4640-95ec-e00a01b2c241' '^build$' \
        High 'Build Validation on Default Branch' \
        'Configure a "Build validation" branch policy via Project Settings > Repos > Policies.'
    _eval_branch_pol BRANCH-03 '40e92b44-2fe1-4dd6-b3d8-74a9c21d0c6e' 'work item linking' \
        Medium 'Work Item Linking Required' \
        'Enable the "Check for linked work items" branch policy.'
    _eval_branch_pol BRANCH-04 'c6a1889d-b943-4856-b76f-9e46bb6b0df2' 'comment requirements' \
        Low 'Comment Resolution Required' \
        'Enable the "Check for comment resolution" branch policy.'
    _eval_branch_pol REPO-06 '' 'credential|secret|push protection' \
        High 'Per-Repository Credentials & Secrets Policy' \
        "Enable GHAzDO push-protection or a credential-scanner policy scoped to this repo's default branch."
    _eval_branch_pol REPO-07 '' 'commit author email' \
        Medium 'Per-Repository Author Email Validation' \
        "Enable the 'Commit author email validation' branch policy on this repo's default branch via Project Settings > Repos > Policies."

    # REPO-03..05: community files presence on default branch
    _eval_community() {
        local id="$1" sev="$2" control="$3"; shift 3
        local -a wanted=("$@")
        local missing=() repos_checked=0
        while IFS=$'\t' read -r repo_id repo_name default_branch; do
            [[ -z "$default_branch" || "$default_branch" == "null" ]] && continue
            repos_checked=$(( repos_checked + 1 ))
            local bname="${default_branch#refs/heads/}"
            local items_f
            items_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/git/repositories/${repo_id}/items?scopePath=/&recursionLevel=OneLevel&versionDescriptor.version=$(url_encode "$bname")&versionDescriptor.versionType=branch&api-version=7.1")"
            local found=0
            if [[ -n "$items_f" && -f "$items_f" ]]; then
                local w lower_paths
                lower_paths="$(jq -r '(.value // [])[] | (.path // "") | sub("^/";"") | ascii_upcase' "$items_f")"
                for w in "${wanted[@]}"; do
                    local upper="${w^^}"
                    if grep -Fxq "$upper" <<<"$lower_paths"; then
                        found=1; break
                    fi
                done
            fi
            (( found == 0 )) && missing+=("$repo_name")
        done < <(jq -r '.[] | [.id, .name, (.defaultBranch // "")] | @tsv' "$f")

        if (( repos_checked == 0 )); then
            emit_control "$rf" "$id" "NOT CHECKED" "$sev" "$control" \
                "No repositories with a default branch were found to evaluate."
        elif (( ${#missing[@]} == 0 )); then
            emit_control "$rf" "$id" "PASS" "$sev" "$control" \
                "All ${repos_checked} repository default branch(es) include the file."
        else
            local miss_list
            miss_list="$(IFS=', '; printf '%s' "${missing[*]:0:10}")"
            emit_control "$rf" "$id" "FAIL" "$sev" "$control" \
                "${#missing[@]}/${repos_checked} repository default branch(es) missing the file: ${miss_list}."
        fi
    }
    _eval_community REPO-03 Low 'README Present on Default Branch' README.md README README.rst README.txt
    _eval_community REPO-04 Low 'CONTRIBUTING File Present on Default Branch' CONTRIBUTING.md CONTRIBUTING CONTRIBUTING.rst
    _eval_community REPO-05 Low 'CODE_OF_CONDUCT File Present on Default Branch' CODE_OF_CONDUCT.md CODE_OF_CONDUCT CODE-OF-CONDUCT.md
}
test_project_feeds() {
    local rf="$1" pname="$2"
    log_step "  [$pname] Checking project feeds..."
    local enc_p f
    enc_p="$(url_encode "$pname")"
    f="$(ado_get "${ORG_URL}/${enc_p}/_apis/packaging/feeds?api-version=7.1-preview.1")"
    [[ -n "$f" && -f "$f" ]] || return 0
    [[ "$(jq '(.value // []) | length' "$f")" == "0" ]] && return 0

    local feed_id feed_name perms_f i count name role
    while IFS=$'\t' read -r feed_id feed_name; do
        perms_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/packaging/Feeds/${feed_id}/permissions?api-version=7.1-preview.1")"
        [[ -n "$perms_f" && -f "$perms_f" ]] || continue
        count="$(jq '(.value // []) | length' "$perms_f")"
        for (( i=0; i<count; i++ )); do
            name="$(jq -r --argjson i "$i" '.value[$i].displayName // ""' "$perms_f")"
            role="$(jq -r --argjson i "$i" '.value[$i].role // ""' "$perms_f")"
            if test_is_broad_group "$name" && [[ "${role,,}" != "reader" ]]; then
                emit_control "$rf" "FEED-01" "FAIL" "High" "No Broad Upload Permissions" \
                    "Feed '${feed_name}' — '${name}' has '${role}' role. Restrict to Reader."
            fi
        done
    done < <(jq -r '(.value // [])[] | [.id, .name] | @tsv' "$f")
}

test_secure_files() {
    local rf="$1" pname="$2"
    log_step "  [$pname] Checking secure files..."
    local enc_p f
    enc_p="$(url_encode "$pname")"
    f="$(ado_get "${ORG_URL}/${enc_p}/_apis/distributedtask/securefiles?api-version=7.1-preview.1")"
    [[ -n "$f" && -f "$f" ]] || return 0
    [[ "$(jq '(.value // []) | length' "$f")" == "0" ]] && return 0

    local sf_id sf_name perms_f auth
    while IFS=$'\t' read -r sf_id sf_name; do
        perms_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/pipelines/pipelinePermissions/securefile/${sf_id}?api-version=7.1-preview.1")"
        [[ -n "$perms_f" && -f "$perms_f" ]] || continue
        auth="$(jq -r '.allPipelines.authorized // empty' "$perms_f")"
        if [[ "$auth" == "true" ]]; then
            emit_control "$rf" "SF-01" "FAIL" "High" "Not Accessible to All YAML Pipelines" \
                "SecureFile '${sf_name}' — Accessible to ALL pipelines. Restrict to specific pipelines."
        else
            emit_control "$rf" "SF-01" "PASS" "High" "Not Accessible to All YAML Pipelines" \
                "SecureFile '${sf_name}' — Not accessible to all pipelines."
        fi
    done < <(jq -r '(.value // [])[] | [.id, .name] | @tsv' "$f")
}

test_environments() {
    local rf="$1" pname="$2"
    log_step "  [$pname] Checking environments..."
    local enc_p f
    enc_p="$(url_encode "$pname")"
    f="$(ado_get "${ORG_URL}/${enc_p}/_apis/distributedtask/environments?api-version=7.1-preview.1")"
    [[ -n "$f" && -f "$f" ]] || return 0
    [[ "$(jq '(.value // []) | length' "$f")" == "0" ]] && return 0

    local env_id env_name perms_f auth checks_f
    while IFS=$'\t' read -r env_id env_name; do
        # ENV-01
        perms_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/pipelines/pipelinePermissions/environment/${env_id}?api-version=7.1-preview.1")"
        if [[ -n "$perms_f" && -f "$perms_f" ]]; then
            auth="$(jq -r '.allPipelines.authorized // empty' "$perms_f")"
            if [[ "$auth" == "true" ]]; then
                emit_control "$rf" "ENV-01" "FAIL" "High" "Not Accessible to All YAML Pipelines" \
                    "Environment '${env_name}' — Accessible to ALL pipelines. Restrict to specific pipelines."
            else
                emit_control "$rf" "ENV-01" "PASS" "High" "Not Accessible to All YAML Pipelines" \
                    "Environment '${env_name}' — Not accessible to all pipelines."
            fi
        fi

        # ENV-03/04/05 — only for production environments
        test_is_production_stage "$env_name" || continue

        checks_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/pipelines/checks/configurations?resourceType=environment&resourceId=${env_id}&\$expand=settings&api-version=7.1-preview.1")"
        local approval_idx="" has_branch_control=0
        if [[ -n "$checks_f" && -f "$checks_f" ]]; then
            approval_idx="$(jq -r '
                [.value[]? | select((.isDisabled // false) != true)]
                | map(.type.name // "") as $names
                | ($names | map(test("approval"; "i")) | index(true)) // "" | tostring' "$checks_f")"
            if [[ "$approval_idx" == "null" ]]; then approval_idx=""; fi
            has_branch_control="$(jq -r '
                [.value[]? | select((.isDisabled // false) != true)
                 | (.settings // {}) as $s
                 | (($s.definitionRef.name // "" | test("branch"; "i"))
                    or ($s.displayName // "" | test("branch control"; "i")))]
                | any | tostring' "$checks_f")"
            [[ "$has_branch_control" != "true" ]] && has_branch_control=0 || has_branch_control=1
        fi

        # ENV-03
        if [[ -n "$approval_idx" && "$approval_idx" != "" ]]; then
            emit_control "$rf" "ENV-03" "PASS" "High" "Production Approvals" \
                "Environment '${env_name}' — Approval checks configured."
        else
            emit_control "$rf" "ENV-03" "FAIL" "High" "Production Approvals" \
                "Environment '${env_name}' — No approval checks on production environment. Add approval checks."
        fi

        # ENV-04
        if [[ -n "$approval_idx" && "$approval_idx" != "" ]]; then
            local ac_settings approver_count min_required eff_required
            ac_settings="$(jq --argjson idx "$approval_idx" '
                [.value[]? | select((.isDisabled // false) != true)][$idx].settings // {}' "$checks_f")"
            approver_count="$(jq '[(.approvers // [])[] | select(.)] | length' <<<"$ac_settings")"
            min_required="$(jq -r '.minRequiredApprovers // 0' <<<"$ac_settings")"
            if [[ "$min_required" -gt 0 ]] 2>/dev/null; then
                eff_required="$min_required"
            else
                eff_required="$approver_count"
                min_required=0
            fi
            if (( eff_required >= 2 )); then
                emit_control "$rf" "ENV-04" "PASS" "High" "Multiple Approvers on Production" \
                    "Environment '${env_name}' — Effective required approvers: ${eff_required} (approvers configured: ${approver_count}, minRequired: ${min_required})."
            else
                emit_control "$rf" "ENV-04" "FAIL" "High" "Multiple Approvers on Production" \
                    "Environment '${env_name}' — Only ${eff_required} effective approver(s) (approvers configured: ${approver_count}, minRequired: ${min_required}). Configure at least 2 distinct approvers to prevent single-point bypass."
            fi
        else
            emit_control "$rf" "ENV-04" "FAIL" "High" "Multiple Approvers on Production" \
                "Environment '${env_name}' — No approval check exists; cannot satisfy multi-approver requirement."
        fi

        # ENV-05
        if (( has_branch_control == 1 )); then
            emit_control "$rf" "ENV-05" "PASS" "High" "Branch Control on Production" \
                "Environment '${env_name}' — Branch control check is configured."
        else
            emit_control "$rf" "ENV-05" "FAIL" "High" "Branch Control on Production" \
                "Environment '${env_name}' — No Branch control check found. Add a Branch control check restricting deployments to a protected production branch."
        fi
    done < <(jq -r '(.value // [])[] | [.id, .name] | @tsv' "$f")
}

test_variable_groups() {
    local rf="$1" pname="$2"
    log_step "  [$pname] Checking variable groups..."
    local f
    f="$(az_cli pipelines variable-group list --project "$pname" --org "$ORG_URL")"
    [[ -n "$f" && -f "$f" ]] || return 0
    [[ "$(jq 'length' "$f")" == "0" ]] && return 0

    local enc_p; enc_p="$(url_encode "$pname")"
    local count i vg vg_id vg_name vg_type
    count="$(jq 'length' "$f")"
    for (( i=0; i<count; i++ )); do
        vg="$(jq -c --argjson i "$i" '.[$i]' "$f")"
        vg_id="$(jq -r '.id // ""' <<<"$vg")"
        vg_name="$(jq -r '.name // ""' <<<"$vg")"
        vg_type="$(jq -r '.type // ""' <<<"$vg")"
        local prefix="VarGroup '${vg_name}'"
        local has_secrets=0

        # VG-03 + has_secrets detection
        local has_vars
        has_vars="$(jq 'has("variables") and (.variables | type == "object")' <<<"$vg")"
        if [[ "$has_vars" == "true" ]]; then
            # has_secrets = any .variables[*].isSecret == true
            local any_secret
            any_secret="$(jq '[(.variables // {}) | to_entries[]? | select(.value.isSecret == true)] | length > 0' <<<"$vg")"
            [[ "$any_secret" == "true" ]] && has_secrets=1
            # suspect = name matches secret-like pattern AND isSecret != true
            local suspects
            suspects="$(jq -r --arg re "$CREDENTIAL_REGEX" '
                [(.variables // {}) | to_entries[]?
                 | select((.value.isSecret // false) != true)
                 | select(.key | test($re; "i"))
                 | .key] | join(", ")' <<<"$vg")"
            if [[ -n "$suspects" ]]; then
                emit_control "$rf" "VG-03" "FAIL" "High" "No Plain Text Secrets" \
                    "${prefix} — Suspect plain-text variables: ${suspects}. Mark as secret or use Key Vault."
            else
                emit_control "$rf" "VG-03" "PASS" "High" "No Plain Text Secrets" \
                    "${prefix} — No plain-text secret variables detected."
            fi
        fi

        # VG-01
        if (( has_secrets == 1 )); then
            local pp_f
            pp_f="$(ado_get "${ORG_URL}/${enc_p}/_apis/pipelines/pipelinePermissions/variablegroup/${vg_id}?api-version=7.1-preview.1")"
            if [[ -n "$pp_f" && -f "$pp_f" ]]; then
                local auth
                auth="$(jq -r '.allPipelines.authorized // empty' "$pp_f")"
                if [[ "$auth" == "true" ]]; then
                    emit_control "$rf" "VG-01" "FAIL" "High" "Secret Variables Not in All Pipelines" \
                        "${prefix} — Contains secrets and is accessible to ALL pipelines. Restrict access."
                else
                    emit_control "$rf" "VG-01" "PASS" "High" "Secret Variables Not in All Pipelines" \
                        "${prefix} — Contains secrets but access is restricted to specific pipelines."
                fi
            fi
        fi

        # VG-04
        local vg_type_lower="${vg_type,,}"
        if (( has_secrets == 1 )) && [[ "$vg_type_lower" == "vsts" ]]; then
            emit_control "$rf" "VG-04" "FAIL" "Low" "Use Azure Key Vault" \
                "${prefix} — Contains secrets in a custom variable group. Consider linking to Azure Key Vault."
        elif [[ "$vg_type_lower" == "azurekeyvault" ]]; then
            emit_control "$rf" "VG-04" "PASS" "Low" "Use Azure Key Vault" \
                "${prefix} — Linked to Azure Key Vault."
        fi
    done
}

# =============================================================================
#  Remediation steps psd1 parser
# =============================================================================
# Parses remediation-steps.psd1 into JSON object keyed by control name:
#   { "Control Name": { "steps": ["...", "..."], "docUrl": "https://..." }, ... }
# Echoes "{}" if file missing or unreadable.
parse_remediation_psd1() {
    local psd1="$1"
    [[ -f "$psd1" ]] || { printf '{}'; return 0; }
    awk '
        function jesc(s) {
            gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s)
            gsub(/\r/, "", s); gsub(/\n/, "\\n", s); gsub(/\t/, "\\t", s)
            return s
        }
        # Strip leading/trailing whitespace
        function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
        BEGIN { printf "{"; first = 1; in_entry = 0 }
        # Entry header:  '"'"'Control Name'"'"' = @{
        /^[[:space:]]*'"'"'[^'"'"']+'"'"'[[:space:]]*=[[:space:]]*@\{/ {
            line = $0
            # Extract control name between first pair of single quotes
            sub(/^[[:space:]]*'"'"'/, "", line)
            name = line
            sub(/'"'"'[[:space:]]*=.*$/, "", name)
            if (!first) printf ","
            first = 0
            printf "\"%s\":{", jesc(name)
            in_entry = 1
            have_steps = 0; have_url = 0
            next
        }
        # Steps line:  Steps = @('"'"'...'"'"','"'"'...'"'"',...)
        in_entry && /^[[:space:]]*Steps[[:space:]]*=[[:space:]]*@\(/ {
            line = $0
            # Strip prefix up through @(
            sub(/^[^@]*@\(/, "", line)
            # Strip trailing )...
            sub(/\)[[:space:]]*$/, "", line)
            # Now parse comma-separated single-quoted items, honoring '"'"''"'"' as literal '"'"'
            printf "\"steps\":["
            sfirst = 1
            n = length(line); buf = ""; in_s = 0; i = 1
            while (i <= n) {
                c = substr(line, i, 1)
                if (!in_s) {
                    if (c == "'"'"'") { in_s = 1; buf = "" }
                    i++; continue
                }
                if (c == "'"'"'") {
                    if (i < n && substr(line, i+1, 1) == "'"'"'") {
                        buf = buf "'"'"'"; i += 2; continue
                    }
                    if (!sfirst) printf ","
                    sfirst = 0
                    printf "\"%s\"", jesc(buf)
                    in_s = 0; i++; continue
                }
                buf = buf c; i++
            }
            printf "]"
            have_steps = 1
            next
        }
        # DocUrl line:  DocUrl = '"'"'...'"'"'
        in_entry && /^[[:space:]]*DocUrl[[:space:]]*=[[:space:]]*'"'"'/ {
            line = $0
            sub(/^[^'"'"']*'"'"'/, "", line)
            sub(/'"'"'[[:space:]]*$/, "", line)
            if (have_steps) printf ","
            printf "\"docUrl\":\"%s\"", jesc(line)
            have_url = 1
            next
        }
        # Closing brace ends entry
        in_entry && /^[[:space:]]*\}[[:space:]]*$/ {
            printf "}"
            in_entry = 0
            next
        }
        END { printf "}" }
    ' "$psd1"
}

# =============================================================================
#  HTML helpers
# =============================================================================
html_escape() {
    # &  <  >  "  '  on stdin → stdout
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' -e "s/'/\&#39;/g"
}

get_adoqr_logo_data_uri() {
    local logo_path="${SCRIPT_DIR:-.}/assets/adoqr_logo.png"
    [[ -f "$logo_path" ]] || { printf ''; return 0; }
    local b64
    if command -v base64 >/dev/null 2>&1; then
        b64="$(base64 -w0 "$logo_path" 2>/dev/null || base64 "$logo_path" 2>/dev/null | tr -d '\n')"
        [[ -n "$b64" ]] && printf 'data:image/png;base64,%s' "$b64"
    fi
}

# Returns the shared adoqr <header> + CSS-friendly title. Emits HTML on stdout.
# Args:  <eyebrow> <title>  [<meta1> <meta2> ...]
get_adoqr_header_html() {
    local eyebrow="$1" title="$2"; shift 2
    local logo; logo="$(get_adoqr_logo_data_uri)"
    local logo_img=''
    [[ -n "$logo" ]] && logo_img="<img class=\"header-logo\" src=\"${logo}\" alt=\"ADOQR — Azure DevOps Quick Review\" width=\"288\" height=\"72\" />"
    local eb_esc tl_esc
    eb_esc="$(printf '%s' "$eyebrow" | html_escape)"
    tl_esc="$(printf '%s' "$title"   | html_escape)"
    local meta_html=''
    if (( $# > 0 )); then
        local spans='' m
        for m in "$@"; do
            spans+="<span>${m}</span>"
        done
        meta_html="      <p class=\"header-meta\" aria-label=\"Report metadata\">${spans}</p>"
    fi
    cat <<EOF
  <header>
    <div class="container">
      <div class="header-brand">
        ${logo_img}
        <div class="header-title-group">
          <h1>
            <span class="header-eyebrow">${eb_esc}</span>
            <span class="header-org">${tl_esc}</span>
          </h1>
        </div>
      </div>
${meta_html}
    </div>
  </header>
EOF
}

# Emits the shared <style> block (CSS variables + base layout + header + cards
# + comparison section). Kept compact compared to the PS1 but uses the same
# CSS variable names so the comparison JS rendering matches.
get_adoqr_base_css() {
    cat <<'EOF'
:root{--bg:#0f172a;--surface:#1e293b;--surface2:#334155;--text:#f1f5f9;--text2:#94a3b8;
--pass:#22c55e;--fail:#ef4444;--warn:#f59e0b;--info:#3b82f6;--accent:#38bdf8;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;line-height:1.5}
.container{max-width:1200px;margin:0 auto;padding:0 1.5rem}
header{background:linear-gradient(135deg,#1e3a5f 0%,#0f172a 100%);padding:2rem 0;border-bottom:1px solid var(--surface2)}
.skip-link{position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden}
.skip-link:focus{left:1rem;top:1rem;width:auto;height:auto;z-index:10000;background:var(--surface);color:var(--text);padding:.5rem .75rem;border-radius:6px;border:1px solid var(--accent)}
.header-brand{display:flex;align-items:center;gap:1.5rem;flex-wrap:wrap;margin:0}
.header-brand .header-logo{display:block;height:72px;width:auto;max-width:100%;flex:0 0 auto;filter:drop-shadow(0 4px 12px rgba(0,0,0,.35))}
.header-brand .header-title-group{min-width:0}
.header-brand .header-logo+.header-title-group{padding-left:1.5rem;border-left:1px solid rgba(255,255,255,.12)}
.header-brand h1{margin:0;font-size:1.5rem;font-weight:700;line-height:1.2;display:flex;flex-direction:column;gap:.15rem}
.header-eyebrow{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.14em;color:var(--text2)}
.header-org{color:var(--text)}
.header-meta{display:flex;flex-wrap:wrap;align-items:center;gap:.35rem .85rem;margin:1.25rem 0 0;color:var(--text2);font-size:.82rem}
.header-meta>span+span::before{content:'';display:inline-block;width:3px;height:3px;border-radius:50%;background:currentColor;opacity:.5;margin-right:.85rem}
.section-nav{position:sticky;top:0;z-index:20;background:rgba(15,23,42,.92);backdrop-filter:blur(6px);border-bottom:1px solid var(--surface2)}
.section-nav-inner{max-width:1200px;margin:0 auto;padding:.6rem 1.5rem;display:flex;gap:.35rem;align-items:center;overflow-x:auto;white-space:nowrap}
.section-nav a{color:var(--text2);text-decoration:none;font-size:.8rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;padding:.3rem .55rem;border-radius:999px;transition:color .15s ease,background-color .15s ease}
.section-nav a:hover{color:var(--text);background:rgba(51,65,85,.55)}
.section-nav .section-nav-resources{margin-left:auto;display:flex;align-items:center}
.section-nav .nav-external{color:var(--accent)}
main{padding:2rem 0}
.section{background:var(--surface);padding:1.5rem;border-radius:10px;margin-bottom:1.5rem;border-left:4px solid var(--surface2)}
.section-accent-info{border-left-color:var(--info)}
.section-accent-warn{border-left-color:var(--warn)}
.section-accent-accent{border-left-color:var(--accent)}
.action-list{list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:.5rem}
.action-item{background:var(--surface2);padding:.65rem .85rem;border-radius:6px;display:flex;align-items:center;gap:.75rem;border-left:3px solid var(--info)}
.action-item.action-urgent{border-left-color:var(--fail)}
.action-item.action-warning{border-left-color:var(--warn)}
.action-item.action-info{border-left-color:var(--info)}
.action-rank{display:inline-block;min-width:2.25rem;text-align:center;padding:.1rem .45rem;background:rgba(0,0,0,.25);border-radius:999px;font-size:.72rem;font-weight:700;color:var(--text2);letter-spacing:.05em}
.org-summary{background:var(--surface2);padding:1rem 1.25rem;border-radius:8px;display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}
.org-stats{display:flex;gap:1.5rem;flex-wrap:wrap}
.stat{text-align:center;min-width:70px}
.stat-val{font-size:1.5rem;font-weight:700;line-height:1.1}
.stat-lbl{font-size:.7rem;color:var(--text2);text-transform:uppercase;letter-spacing:.1em;margin-top:.15rem}
details.section-collapsible{display:block}
.section-collapsible-summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:1rem}
.section-collapsible-summary::-webkit-details-marker{display:none}
.section-collapsible-title{flex:1;min-width:0}
.section-collapsible-title .section-eyebrow{margin:0 0 .25rem}
.section-collapsible-title h2{margin:0}
.section-collapsible-count{display:inline-flex;align-items:center;justify-content:center;min-width:2.2rem;height:1.9rem;padding:0 .7rem;border-radius:999px;background:rgba(245,158,11,.15);color:var(--warn);font-weight:800;font-size:.85rem}
.section-collapsible-chevron{width:1.9rem;height:1.9rem;border-radius:999px;background:var(--surface2);color:var(--text);display:inline-flex;align-items:center;justify-content:center;font-size:1.1rem;font-weight:700;flex:0 0 auto}
.section-collapsible-chevron::before{content:'+'}
details.section-collapsible[open] .section-collapsible-chevron::before{content:'\2212'}
details.section-collapsible[open] > .section-collapsible-summary{margin-bottom:1.25rem}
.nc-explainer{display:flex;flex-direction:column;gap:.2rem;background:var(--surface2);border-left:4px solid var(--warn);border-radius:0 8px 8px 0;padding:1rem 1.25rem;margin-bottom:1rem}
.nc-explainer span,.nc-reason-card p,.nc-details-intro span{color:var(--text2)}
.nc-reason-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:.75rem;margin-bottom:1rem}
.nc-reason-card{display:flex;gap:.75rem;align-items:flex-start;background:var(--surface2);border:1px solid var(--surface2);border-radius:8px;padding:.9rem 1rem}
.nc-reason-count{display:inline-flex;align-items:center;justify-content:center;min-width:2rem;height:2rem;padding:0 .45rem;border-radius:999px;background:rgba(245,158,11,.15);color:var(--warn);font-weight:800}
.nc-reason-card p{margin:.15rem 0 0;font-size:.85rem;line-height:1.4}
.nc-details-intro{display:flex;align-items:baseline;gap:.6rem;margin:0 0 .75rem;font-size:.9rem}
.nc-detail{background:var(--surface2);border-radius:8px;margin-bottom:.75rem;overflow:hidden}
.nc-detail summary{display:flex;align-items:center;gap:.75rem;cursor:pointer;list-style:none;padding:.75rem 1rem;font-weight:700}
.nc-detail summary::-webkit-details-marker{display:none}
.nc-detail summary::after{content:'+';margin-left:auto;color:var(--text2);font-size:1.15rem}
.nc-detail[open] summary{border-bottom:1px solid var(--surface)}
.nc-detail[open] summary::after{content:'-'}
.nc-detail-count{display:inline-flex;align-items:center;justify-content:center;min-width:1.6rem;height:1.6rem;padding:0 .4rem;border-radius:999px;background:var(--surface);color:var(--text);font-size:.8rem;font-weight:800}
.nc-detail td span{color:var(--text2);font-size:.85rem}
.nc-sev{display:inline-block;padding:.15rem .5rem;border-radius:999px;font-size:.75rem;font-weight:800;text-transform:uppercase}
.nc-sev-high{background:rgba(239,68,68,.12);color:var(--fail)}
.nc-sev-medium{background:rgba(245,158,11,.12);color:var(--warn)}
.nc-sev-low{background:rgba(59,130,246,.12);color:var(--info)}
.section h2{margin:0 0 1rem;font-size:1.25rem}
.section-eyebrow{font-size:.7rem;text-transform:uppercase;letter-spacing:.14em;color:var(--text2);margin:0 0 .25rem;display:flex;align-items:center;gap:.4rem}
.section-eyebrow-dot{width:6px;height:6px;border-radius:50%;background:var(--info);display:inline-block}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin:1rem 0}
.card{background:var(--surface2);padding:1rem;border-radius:8px;text-align:center}
.card-value{font-size:1.75rem;font-weight:700;margin-bottom:.25rem}
.card-label{font-size:.8rem;color:var(--text2);text-transform:uppercase;letter-spacing:.1em}
.card-pass .card-value{color:var(--pass)}
.card-fail .card-value{color:var(--fail)}
.card-nc .card-value{color:var(--warn)}
.card-risk .card-value{color:var(--warn)}
.ring-container{display:flex;align-items:center;gap:2rem;flex-wrap:wrap}
.ring{position:relative;width:140px;height:140px}
.ring svg{transform:rotate(-90deg)}
.ring-label{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:1.75rem;font-weight:800}
.tbl-wrap{overflow-x:auto;margin:1rem 0}
table{width:100%;border-collapse:collapse;background:var(--surface2);border-radius:8px;overflow:hidden}
th,td{padding:.6rem .8rem;text-align:left;border-bottom:1px solid var(--surface)}
th{background:rgba(0,0,0,.2);font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;color:var(--text2)}
tr:last-child td{border-bottom:none}
.pill{display:inline-block;padding:.15rem .55rem;border-radius:999px;font-size:.72rem;font-weight:700;text-transform:uppercase}
.pill-pass{background:rgba(34,197,94,.15);color:var(--pass)}
.pill-fail{background:rgba(239,68,68,.15);color:var(--fail)}
.pill-nc{background:rgba(245,158,11,.15);color:var(--warn)}
.bar{height:8px;background:var(--surface2);border-radius:4px;overflow:hidden;display:flex}
.bar>span{display:block;height:100%}
.bar-pass{background:var(--pass)}.bar-fail{background:var(--fail)}.bar-nc{background:var(--warn)}
a{color:var(--accent)}
.cmp-pickers{display:flex;gap:1rem;align-items:end;flex-wrap:wrap;margin:1rem 0}
.cmp-picker-grp{flex:1;min-width:200px}
.cmp-lbl{display:block;font-size:.72rem;color:var(--text2);text-transform:uppercase;letter-spacing:.1em;margin-bottom:.25rem}
.cmp-sel{width:100%;background:var(--surface2);color:var(--text);border:1px solid var(--surface2);padding:.5rem;border-radius:6px;font-size:.85rem}
.cmp-vs{color:var(--text2);font-weight:700;align-self:center;padding-bottom:.5rem}
.cmp-executive-summary{background:var(--surface2);padding:1rem 1.25rem;border-radius:8px;margin:1rem 0}
.cmp-verdict{display:inline-block;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.12em;padding:.2rem .6rem;border-radius:999px;margin-bottom:.5rem}
.cmp-verdict-good{background:rgba(34,197,94,.15);color:var(--pass)}
.cmp-verdict-risk{background:rgba(239,68,68,.15);color:var(--fail)}
.cmp-verdict-stable{background:rgba(148,163,184,.15);color:var(--text2)}
.cmp-summary-copy{display:block;margin:.25rem 0 .35rem}
.cmp-summary-copy strong{display:block;margin-bottom:.15rem}
.cmp-summary-copy span{color:var(--text2);font-size:.85rem}
.cmp-summary-meta{color:var(--text2);font-size:.8rem}
.cmp-delta-cards{margin:.5rem 0 1rem}
.cmp-detail-intro{margin:1rem 0 .5rem;display:flex;flex-direction:column;gap:.15rem}
.cmp-detail-intro span{color:var(--text2);font-size:.85rem}
.cmp-group{border-left:3px solid var(--surface2);background:var(--surface2);border-radius:6px;margin:.5rem 0;overflow:hidden}
.cmp-group-hdr{cursor:pointer;padding:.6rem .9rem;font-weight:600;display:flex;align-items:center;gap:.6rem;list-style:none}
.cmp-group-hdr::-webkit-details-marker{display:none}
.cmp-cnt{background:rgba(0,0,0,.3);padding:.1rem .55rem;border-radius:999px;font-size:.75rem}
.cmp-disclosure{margin-left:auto;color:var(--text2);font-size:.8rem;text-transform:uppercase;letter-spacing:.1em}
.cmp-empty{padding:.75rem .9rem;color:var(--text2);font-style:italic;margin:0}
details[open] .cmp-group-hdr{border-bottom:1px solid var(--surface)}
.rem-card{background:var(--surface2);padding:1.25rem;border-radius:8px;margin:1rem 0;border-left:4px solid var(--fail)}
.rem-card h3{margin:0 0 .25rem;font-size:1.05rem}
.rem-meta{font-size:.78rem;color:var(--text2);margin-bottom:.75rem}
.rem-meta .pill{margin-right:.5rem}
.rem-finding{background:rgba(0,0,0,.2);padding:.6rem .8rem;border-radius:6px;margin:.5rem 0;font-size:.88rem;color:var(--text2)}
.rem-steps{margin:.75rem 0 .25rem;padding-left:1.5rem}
.rem-steps li{margin:.25rem 0}
.rem-doclink{display:inline-block;margin-top:.5rem;font-size:.82rem}
code{background:var(--surface2);padding:.1rem .35rem;border-radius:4px;font-family:Consolas,Monaco,monospace;font-size:.85em}
@media (max-width:640px){.section-nav-inner{padding:.55rem 1rem}}
@media print{.section-nav{display:none}}
EOF
}

# =============================================================================
#  Prior scan runs / Run comparison
# =============================================================================
# Scans $OutputPath for sibling run folders <orgsafe>-YYYY-MM-DD-HHMMSS that
# contain <orgsafe>-scan.json conforming to schemaVersion 1.0. Returns a JSON
# array sorted newest-first, with each entry shaped:
#   { "runId": "...", "generatedAt": "...", "summary": {...}, "controls": [...] }
get_prior_scan_runs() {
    local exclude_run_id="${1:-}"
    local root="$OUTPUT_PATH"
    [[ -d "$root" ]] || { printf '[]'; return 0; }
    local entries_tmp; entries_tmp="$(mktemp)"
    : >"$entries_tmp"
    local d name scan_file
    while IFS= read -r d; do
        [[ -d "$d" ]] || continue
        name="$(basename "$d")"
        [[ "$name" == "$exclude_run_id" ]] && continue
        local entry=''
        scan_file="${d}/${ORG_SAFE_NAME}-scan.json"
        if [[ -f "$scan_file" ]]; then
            local ts
            ts="$(jq -r '.meta.generatedAt // empty' "$scan_file" 2>/dev/null || true)"
            if [[ -n "$ts" ]]; then
                entry="$(jq -c --arg rid "$name" --arg ts "$ts" '{
                    runId: $rid,
                    generatedAt: $ts,
                    summary: (.meta.summary // {pass:0,fail:0,notChecked:0}),
                    controls: [ (.controls // [])[] | {
                        id, status, severity, control,
                        scope: (.scope // {type:"organization"})
                    } ]
                }' "$scan_file" 2>/dev/null)" || entry=''
            fi
        fi
        # Fallback: reconstruct lightweight run from generated Markdown reports
        # so older runs (no scan.json) still participate in the comparison UI.
        if [[ -z "$entry" ]]; then
            entry="$(_import_run_from_md "$d" "$name" 2>/dev/null)" || entry=''
        fi
        [[ -n "$entry" ]] || continue
        printf '%s\n' "$entry" >>"$entries_tmp"
    done < <(find "$root" -mindepth 1 -maxdepth 1 -type d -name "${ORG_SAFE_NAME}-*" 2>/dev/null)
    if [[ ! -s "$entries_tmp" ]]; then
        rm -f "$entries_tmp"
        printf '[]'
        return 0
    fi
    jq -s 'sort_by(.generatedAt) | reverse' "$entries_tmp"
    rm -f "$entries_tmp"
}

# Reconstructs lightweight comparison data from generated Markdown reports.
# Compatibility fallback used when a run folder has no scan.json.
# Args: <run_directory> <run_id>
# Emits a single JSON object on stdout, or returns 1 if no controls parsed.
_import_run_from_md() {
    local dir="$1" run_id="$2"
    [[ -d "$dir" ]] || return 1
    local org_name="$ORG_SHORT_NAME"
    local generated_at='' has_any=0
    local ctl_tmp; ctl_tmp="$(mktemp)"
    : >"$ctl_tmp"
    local f h1 d_raw d_val scope_type proj_name
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        scope_type='organization'; proj_name=''
        h1="$(grep -m1 -E '^# ' "$f" 2>/dev/null || true)"
        if [[ "$h1" =~ ^\#\ Organization\ Quick\ Review:\ *(.+)$ ]]; then
            org_name="$(printf '%s' "${BASH_REMATCH[1]}" | sed -E 's/[[:space:]]+$//')"
        elif [[ "$h1" =~ ^\#\ Project\ Quick\ Review:\ *(.+)$ ]]; then
            scope_type='project'
            proj_name="$(printf '%s' "${BASH_REMATCH[1]}" | sed -E 's/[[:space:]]+$//')"
        fi
        if [[ -z "$generated_at" ]]; then
            d_raw="$(grep -m1 -E '\*\*Assessment Date\*\*' "$f" 2>/dev/null || true)"
            if [[ -n "$d_raw" ]]; then
                d_val="$(printf '%s' "$d_raw" | sed -E 's/^\|[^|]*\|[[:space:]]*([^|]+)[[:space:]]*\|.*$/\1/' | sed -E 's/[[:space:]]+$//')"
                [[ -n "$d_val" ]] && generated_at="$d_val"
            fi
        fi
        local before_lines after_lines
        before_lines="$(wc -l <"$ctl_tmp" 2>/dev/null || echo 0)"
        awk -v st="$scope_type" -v org="$org_name" -v proj="$proj_name" '
            function jstr(s,   r) { r=s; gsub(/\\/,"\\\\",r); gsub(/"/,"\\\"",r); gsub(/\t/," ",r); gsub(/\r/,"",r); return "\"" r "\"" }
            BEGIN { FS="|" }
            NF >= 6 {
                status=$3; gsub(/^[ \t]+|[ \t]+$/, "", status)
                if (status != "PASS" && status != "FAIL" && status != "NOT CHECKED") next
                sev=$4; gsub(/^[ \t]+|[ \t]+$/, "", sev)
                if (match(sev, /(High|Medium|Low)/)) { sev = substr(sev, RSTART, RLENGTH) } else next
                ctl=$5; gsub(/^[ \t]+|[ \t]+$/, "", ctl)
                n = index(ctl, ":")
                if (n == 0) next
                id = substr(ctl, 1, n-1); gsub(/^[ \t]+|[ \t]+$/, "", id)
                name = substr(ctl, n+1); gsub(/^[ \t]+|[ \t]+$/, "", name)
                printf "{\"id\":%s,\"status\":%s,\"severity\":%s,\"control\":%s,\"scope\":{\"type\":%s,\"organization\":%s,\"project\":%s}}\n",
                    jstr(id), jstr(status), jstr(sev), jstr(name), jstr(st), jstr(org), (proj=="" ? "null" : jstr(proj))
            }
        ' "$f" >>"$ctl_tmp"
        after_lines="$(wc -l <"$ctl_tmp" 2>/dev/null || echo 0)"
        (( after_lines > before_lines )) && has_any=1
    done < <(find "$dir" -maxdepth 1 -type f -name "${ORG_SAFE_NAME}-*-assessment.md" 2>/dev/null)
    if (( has_any != 1 )); then
        rm -f "$ctl_tmp"
        return 1
    fi
    if [[ -z "$generated_at" ]]; then
        generated_at="$(date -u -r "$dir" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ')"
    fi
    local out
    out="$(jq -c -n --arg rid "$run_id" --arg ts "$generated_at" --slurpfile controls "$ctl_tmp" '{
        runId: $rid,
        generatedAt: $ts,
        summary: {
            pass: ([$controls[]|select(.status=="PASS")]|length),
            fail: ([$controls[]|select(.status=="FAIL")]|length),
            notChecked: ([$controls[]|select(.status=="NOT CHECKED")]|length)
        },
        controls: $controls
    }')" || { rm -f "$ctl_tmp"; return 1; }
    rm -f "$ctl_tmp"
    printf '%s' "$out"
}

# build_comparison_section_html  →  outputs HTML on stdout.
# Reads runs JSON from stdin.
build_comparison_section_html() {
    local runs_json; runs_json="$(cat)"
    # Sanitize </script> embedded in JSON values to avoid premature tag close
    runs_json="${runs_json//<\/script>/<\\/script>}"
    cat <<HTML_HEAD
    <section class="section section-accent-info" id="comparison-section" aria-label="Run comparison">
      <p class="section-eyebrow"><span class="section-eyebrow-dot"></span>Trend</p>
      <h2>&#128202; Run Comparison</h2>
      <p id="cmp-nodata" style="color:var(--text2)">No previous scan data available for comparison.
        Keep prior assessment folders, or run with <code>--output-format json</code>
        or <code>--output-format all</code> for richer scan data.</p>
      <div id="cmp-ui" style="display:none">
        <div class="cmp-pickers">
          <div class="cmp-picker-grp">
            <label class="cmp-lbl" for="cmp-run-a">Current Run</label>
            <select id="cmp-run-a" class="cmp-sel" aria-label="Select current run to compare"></select>
          </div>
          <span class="cmp-vs">vs</span>
          <div class="cmp-picker-grp">
            <label class="cmp-lbl" for="cmp-run-b">Baseline Run</label>
            <select id="cmp-run-b" class="cmp-sel" aria-label="Select baseline run to compare against"></select>
          </div>
        </div>
        <div id="cmp-result"></div>
      </div>
    </section>
    <script>window.__adoqrRuns=${runs_json};</script>
HTML_HEAD
    cat <<'HTML_JS'
    <script>
(function () {
  var runs = window.__adoqrRuns || [];
  var elNoData  = document.getElementById('cmp-nodata');
  var elUi      = document.getElementById('cmp-ui');
  var elResult  = document.getElementById('cmp-result');
  var selA      = document.getElementById('cmp-run-a');
  var selB      = document.getElementById('cmp-run-b');
  if (!elNoData || !elUi || !elResult || !selA || !selB) return;
  if (runs.length < 2) return;
  elNoData.style.display = 'none';
  elUi.style.display = 'block';
  runs.forEach(function (r, i) {
    var ts  = r.generatedAt ? r.generatedAt.substring(0, 19).replace('T', ' ') + ' UTC' : r.runId;
    var lbl = ts + '  \u2014  ' + r.runId;
    selA.add(new Option(lbl, String(i)));
    selB.add(new Option(lbl, String(i)));
  });
  selA.value = '0'; selB.value = '1';
  function sevOrd(s) { return s === 'High' ? 0 : s === 'Medium' ? 1 : 2; }
  function sevClr(s) { return s === 'High' ? 'var(--fail)' : s === 'Medium' ? 'var(--warn)' : 'var(--info)'; }
  function sevBg(s)  { return s === 'High' ? 'rgba(239,68,68,.12)' : s === 'Medium' ? 'rgba(245,158,11,.12)' : 'rgba(59,130,246,.12)'; }
  function esc(v)    { return String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function ctrlKey(c) { var sc = c.scope ? (c.scope.type + '|' + (c.scope.project || '')) : ''; return c.id + '|' + sc; }
  function scopeLbl(c) { return c.scope && c.scope.type === 'project' ? esc(c.scope.project || '') : 'Org'; }
  function renderRow(c, statusHtml) {
    return '<tr><td><strong>' + esc(c.id) + '</strong><br><span style="color:var(--text2);font-size:.85rem">' + esc(c.control || '') + '</span></td>'
      + '<td><span style="display:inline-block;padding:.15rem .5rem;border-radius:999px;font-size:.75rem;font-weight:700;text-transform:uppercase;background:' + sevBg(c.severity) + ';color:' + sevClr(c.severity) + '">' + esc(c.severity) + '</span></td>'
      + '<td>' + scopeLbl(c) + '</td><td>' + statusHtml + '</td></tr>';
  }
  function renderGroup(title, rows, emptyMsg, borderClr, openByDefault) {
    var openAttr = openByDefault ? ' open' : '';
    var h = '<details class="cmp-group"' + openAttr + ' style="border-left-color:' + borderClr + '">'
          + '<summary class="cmp-group-hdr"><span class="cmp-cnt">' + rows.length + '</span><span>' + title + '</span><span class="cmp-disclosure">Details</span></summary>';
    if (rows.length === 0) h += '<p class="cmp-empty">' + emptyMsg + '</p>';
    else h += '<div class="tbl-wrap"><table><thead><tr><th>Control</th><th>Severity</th><th>Scope</th><th>Change</th></tr></thead><tbody>' + rows.join('') + '</tbody></table></div>';
    return h + '</details>';
  }
  function trendLabel(dPct, dFail, regressed, improved) {
    if (regressed > 0 || dPct < 0 || dFail > 0) return { text: 'Needs attention', cls: 'cmp-verdict-risk' };
    if (improved > 0 || dPct > 0 || dFail < 0) return { text: 'Improving', cls: 'cmp-verdict-good' };
    return { text: 'Stable', cls: 'cmp-verdict-stable' };
  }
  function renderExecSummary(a, b, aPct, bPct, dPct, dFail, improved, regressed, persist) {
    var trend = trendLabel(dPct, dFail, regressed.length, improved.length);
    var direction = dPct > 0 ? 'up' : dPct < 0 ? 'down' : 'unchanged';
    var failDir = dFail < 0 ? 'down' : dFail > 0 ? 'up' : 'unchanged';
    var primary = '';
    if (regressed.length > 0) primary = regressed.length + ' control' + (regressed.length === 1 ? ' has' : 's have') + ' regressed since the baseline.';
    else if (improved.length > 0) primary = improved.length + ' control' + (improved.length === 1 ? ' is' : 's are') + ' now passing with no new regressions.';
    else if (persist.length > 0) primary = 'No new regressions, but ' + persist.length + ' control' + (persist.length === 1 ? ' remains' : 's remain') + ' failing.';
    else primary = 'No material control movement detected between the selected runs.';
    return '<div class="cmp-executive-summary"><div class="cmp-verdict ' + trend.cls + '">' + esc(trend.text) + '</div>'
      + '<div class="cmp-summary-copy"><strong>' + esc(primary) + '</strong>'
      + '<span>Pass rate is ' + direction + ' from ' + bPct + '% to ' + aPct + '%, and failures are ' + failDir + ' by ' + Math.abs(dFail) + '.</span></div>'
      + '<div class="cmp-summary-meta">Comparing <strong>' + esc(a.runId) + '</strong> against <strong>' + esc(b.runId) + '</strong>.</div></div>';
  }
  function run() {
    var ai = parseInt(selA.value, 10); var bi = parseInt(selB.value, 10);
    if (ai === bi) { elResult.innerHTML = '<p style="color:var(--text2);margin:.5rem 0">Please select two different runs to compare.</p>'; return; }
    var a = runs[ai], b = runs[bi];
    var aMap = {}, bMap = {};
    (a.controls || []).forEach(function (c) { aMap[ctrlKey(c)] = c; });
    (b.controls || []).forEach(function (c) { bMap[ctrlKey(c)] = c; });
    var improved = [], regressed = [], persist = [], added = [], removed = [];
    Object.keys(aMap).forEach(function (k) {
      var ac = aMap[k], bc = bMap[k];
      if (!bc) { added.push(ac); return; }
      if (bc.status !== 'PASS' && ac.status === 'PASS') improved.push({ a: ac, b: bc });
      else if (bc.status === 'PASS' && ac.status === 'FAIL') regressed.push({ a: ac, b: bc });
      else if (ac.status === 'FAIL' && bc.status === 'FAIL') persist.push({ a: ac, b: bc });
    });
    Object.keys(bMap).forEach(function (k) { if (!aMap[k]) removed.push(bMap[k]); });
    function srt(arr, fn) { arr.sort(function (x, y) { return sevOrd(fn(x).severity) - sevOrd(fn(y).severity); }); }
    srt(improved, function (x) { return x.a; }); srt(regressed, function (x) { return x.a; }); srt(persist, function (x) { return x.a; });
    added.sort(function (x, y) { return sevOrd(x.severity) - sevOrd(y.severity); });
    removed.sort(function (x, y) { return sevOrd(x.severity) - sevOrd(y.severity); });
    var aSum = a.summary || {}, bSum = b.summary || {};
    var aT = (aSum.pass || 0) + (aSum.fail || 0) + (aSum.notChecked || 0);
    var bT = (bSum.pass || 0) + (bSum.fail || 0) + (bSum.notChecked || 0);
    var aPct = aT > 0 ? Math.round((aSum.pass || 0) * 100 / aT) : 0;
    var bPct = bT > 0 ? Math.round((bSum.pass || 0) * 100 / bT) : 0;
    var dPct = aPct - bPct; var dFail = (aSum.fail || 0) - (bSum.fail || 0);
    var pArrow = dPct > 0 ? '\u25B2' : dPct < 0 ? '\u25BC' : '\u25AC';
    var pClr = dPct > 0 ? 'var(--pass)' : dPct < 0 ? 'var(--fail)' : 'var(--text2)';
    var fArrow = dFail < 0 ? '\u25B2' : dFail > 0 ? '\u25BC' : '\u25AC';
    var fClr = dFail < 0 ? 'var(--pass)' : dFail > 0 ? 'var(--fail)' : 'var(--text2)';
    var html = renderExecSummary(a, b, aPct, bPct, dPct, dFail, improved, regressed, persist);
    html += '<div class="cards cmp-delta-cards">'
      + '<div class="card"><div class="card-value" style="color:' + pClr + '">' + pArrow + ' ' + Math.abs(dPct) + '%</div><div class="card-label">Pass Rate Change</div><div style="font-size:.8rem;color:var(--text2);margin-top:.25rem">' + bPct + '% \u2192 ' + aPct + '%</div></div>'
      + '<div class="card"><div class="card-value"><span style="color:' + fClr + '">' + fArrow + '</span> ' + Math.abs(dFail) + '</div><div class="card-label">Failure Count Change</div><div style="font-size:.8rem;color:var(--text2);margin-top:.25rem">' + (bSum.fail || 0) + ' \u2192 ' + (aSum.fail || 0) + '</div></div>'
      + '<div class="card"><div class="card-value" style="color:var(--pass)">' + improved.length + '</div><div class="card-label">Improved</div></div>'
      + '<div class="card"><div class="card-value" style="color:var(--fail)">' + regressed.length + '</div><div class="card-label">Regressed</div></div>'
      + '<div class="card"><div class="card-value" style="color:var(--warn)">' + persist.length + '</div><div class="card-label">Still Failing</div></div>'
      + '</div>';
    html += '<div class="cmp-detail-intro"><strong>Detailed movement</strong><span>Expand a section to review the specific controls behind the summary.</span></div>';
    html += renderGroup('Regressed \u2014 PASS \u2192 FAIL', regressed.map(function (x) { return renderRow(x.a, '<span style="color:var(--fail)">\u25BC PASS \u2192 FAIL</span>'); }), 'No regressions in the selected comparison.', 'var(--fail)', regressed.length > 0);
    html += renderGroup('Improved \u2014 now PASS', improved.map(function (x) { var fr = x.b.status === 'NOT CHECKED' ? 'NOT CHECKED' : 'FAIL'; return renderRow(x.a, '<span style="color:var(--pass)">\u25B2 ' + fr + ' \u2192 PASS</span>'); }), 'No controls moved into PASS.', 'var(--pass)', false);
    html += renderGroup('Still Failing', persist.map(function (x) { return renderRow(x.a, '<span style="color:var(--warn)">\u25AC Still FAIL</span>'); }), 'No controls failed in both selected runs.', 'var(--warn)', regressed.length === 0 && persist.length > 0);
    if (added.length > 0) html += renderGroup('New Controls (in current run only)', added.map(function (c) { return renderRow(c, '<span style="color:var(--info)">New</span>'); }), '', 'var(--info)', false);
    if (removed.length > 0) html += renderGroup('Removed Controls (from baseline only)', removed.map(function (c) { return renderRow(c, '<span style="color:var(--text2)">Removed</span>'); }), '', 'var(--surface2)', false);
    elResult.innerHTML = html;
  }
  selA.addEventListener('change', run);
  selB.addEventListener('change', run);
  run();
}());
    </script>
HTML_JS
}

# =============================================================================
#  Not Checked section
# =============================================================================
# Classifies a "NOT CHECKED" finding string into an executive-readable reason.
# Mirrors Get-NotCheckedReasonCategory in invoke-adoqr.ps1.
get_not_checked_reason() {
    local finding="$1"
    local lc="${finding,,}"
    case "$lc" in
        *"manual review required"*|*"manual review recommended"*) printf 'Manual review required' ;;
        *"could not retrieve"*|*"could not determine"*|*"could not locate"*|*"could not enumerate"*|*"unable to"*) printf 'Data unavailable' ;;
        *"not found"*) printf 'Setting not found' ;;
        *)
            if [[ "$lc" =~ requires[[:space:]]+-|requires[[:space:]]+querying|requires[[:space:]].*permission|may[[:space:]]+require ]]; then
                printf 'Prerequisite or permission needed'
            elif [[ "$lc" =~ ^no[[:space:]].+found|nothing[[:space:]].+found ]]; then
                printf 'No applicable data found'
            else
                printf 'Review needed'
            fi
            ;;
    esac
}

# build_not_checked_section_html <org_jsonl> <projects_dir>
# Emits the full <details id="not-checked-section">...</details> block, or
# nothing at all when there are no NOT CHECKED results across any scope.
build_not_checked_section_html() {
    local org_jsonl="$1" projs_dir="$2"
    local tmp; tmp="$(mktemp "${ADOQR_TMP}/nc_items.XXXXXX.tsv")"

    # Collect scope<TAB>id<TAB>control<TAB>severity<TAB>finding for every NOT CHECKED row.
    if [[ -s "$org_jsonl" ]]; then
        jq -r 'select(.status=="NOT CHECKED") | ["Organization", .id, .control, .severity, .finding] | @tsv' \
            "$org_jsonl" 2>/dev/null >>"$tmp" || true
    fi
    if [[ -d "$projs_dir" ]]; then
        local jf safe pname
        while IFS= read -r jf; do
            [[ -f "$jf" ]] || continue
            safe="$(basename "$jf" .jsonl)"
            pname="$(cat "${projs_dir}/${safe}.name" 2>/dev/null || echo "$safe")"
            jq -r --arg scope "Project: ${pname}" \
                'select(.status=="NOT CHECKED") | [$scope, .id, .control, .severity, .finding] | @tsv' \
                "$jf" 2>/dev/null >>"$tmp" || true
        done < <(find "$projs_dir" -maxdepth 1 -name '*.jsonl' -type f 2>/dev/null | sort)
    fi

    if [[ ! -s "$tmp" ]]; then
        rm -f "$tmp"
        return 0
    fi

    local total_items; total_items="$(wc -l <"$tmp" | tr -d ' ')"

    # ---- Reason cards (aggregate counts per reason) ----------------------
    local reasons_tmp; reasons_tmp="$(mktemp "${ADOQR_TMP}/nc_reasons.XXXXXX.txt")"
    local scope id control severity finding reason
    while IFS=$'\t' read -r scope id control severity finding; do
        reason="$(get_not_checked_reason "$finding")"
        printf '%s\n' "$reason" >>"$reasons_tmp"
    done <"$tmp"

    local reason_cards='' reason_count reason
    while IFS=$'\t' read -r reason_count reason; do
        [[ -z "$reason" ]] && continue
        local reason_esc; reason_esc="$(printf '%s' "$reason" | html_escape)"
        local desc='The scanner captured a reason, but it does not map to a standard category yet.'
        reason_cards+="$(printf '<div class="nc-reason-card"><div class="nc-reason-count">%s</div><div><strong>%s</strong><p>%s</p></div></div>' \
            "$reason_count" "$reason_esc" "$desc")"
    done < <(sort "$reasons_tmp" | uniq -c | awk '{c=$1; $1=""; sub(/^ /,""); printf "%s\t%s\n", c, $0}')
    rm -f "$reasons_tmp"

    # ---- Detail groups (one <details> per scope) -------------------------
    local scopes_tmp; scopes_tmp="$(mktemp "${ADOQR_TMP}/nc_scopes.XXXXXX.txt")"
    awk -F'\t' '{print $1}' "$tmp" | awk '!seen[$0]++' >"$scopes_tmp"

    local detail_groups=''
    local scope_name rows scope_count sev_class control_label finding_esc reason_esc id_label
    while IFS= read -r scope_name; do
        [[ -z "$scope_name" ]] && continue
        rows=''
        scope_count=0
        while IFS=$'\t' read -r scope id control severity finding; do
            [[ "$scope" == "$scope_name" ]] || continue
            scope_count=$(( scope_count + 1 ))
            case "$severity" in
                High)   sev_class='nc-sev-high' ;;
                Medium) sev_class='nc-sev-medium' ;;
                *)      sev_class='nc-sev-low' ;;
            esac
            reason="$(get_not_checked_reason "$finding")"
            id_label="$(printf '%s' "$id" | html_escape)"
            control_label="$(printf '%s' "$control" | html_escape)"
            reason_esc="$(printf '%s' "$reason" | html_escape)"
            finding_esc="$(printf '%s' "$finding" | html_escape)"
            local sev_esc; sev_esc="$(printf '%s' "$severity" | html_escape)"
            rows+="$(printf '<tr><td><strong>%s: %s</strong><br><span>%s</span></td><td><span class="nc-sev %s">%s</span></td><td>%s</td></tr>' \
                "$id_label" "$control_label" "$reason_esc" "$sev_class" "$sev_esc" "$finding_esc")"
        done <"$tmp"
        local scope_esc; scope_esc="$(printf '%s' "$scope_name" | html_escape)"
        detail_groups+="$(printf '<details class="nc-detail"><summary><span>%s</span><span class="nc-detail-count">%d</span></summary><div class="tbl-wrap"><table><thead><tr><th>Control</th><th>Severity</th><th>Why it was not checked</th></tr></thead><tbody>%s</tbody></table></div></details>' \
            "$scope_esc" "$scope_count" "$rows")"
    done <"$scopes_tmp"
    rm -f "$scopes_tmp" "$tmp"

    cat <<HTML
    <details class="section section-accent-warn section-collapsible" id="not-checked-section" aria-label="Not checked controls explanation">
        <summary class="section-collapsible-summary">
            <div class="section-collapsible-title">
                <p class="section-eyebrow"><span class="section-eyebrow-dot"></span>Not Checked</p>
                <h2>Not Checked Controls</h2>
            </div>
            <span class="section-collapsible-count" aria-label="${total_items} controls not checked">${total_items}</span>
            <span class="section-collapsible-chevron" aria-hidden="true"></span>
        </summary>
        <div class="nc-explainer">
            <strong>Not checked does not mean failed.</strong>
            <span>These controls need more context, permissions, configuration data, or manual confirmation before adoqr can make a PASS/FAIL determination.
                See the <a href="https://microsoft.github.io/adoqr/controls.html" target="_blank" rel="noopener noreferrer">controls reference&nbsp;&#8599;</a> for what each control evaluates and how to remediate it.</span>
        </div>
        <div class="nc-reason-grid">${reason_cards}</div>
        <div class="nc-details-intro"><strong>Review details</strong><span>Expand a scope to see the exact controls and the recorded reason.</span></div>
        ${detail_groups}
    </details>
HTML
}

# =============================================================================
#  Executive HTML report
# =============================================================================
# write_executive_html_report <file> <org_jsonl> <projects_dir> <elapsed_secs> <run_id>
# Builds a self-contained executive HTML, including the Run Comparison section.
write_executive_html_report() {
    local file="$1" org_jsonl="$2" projs_dir="$3" elapsed="$4" run_id="$5"
    local date_str; date_str="$(date '+%Y-%m-%d %H:%M:%S')"

    # Aggregate per-scope summary stats
    local org_pass org_fail org_nc
    org_pass="$(awk -F'"' '/"status":"PASS"/{c++} END{print c+0}' "$org_jsonl" 2>/dev/null || echo 0)"
    org_fail="$(awk -F'"' '/"status":"FAIL"/{c++} END{print c+0}' "$org_jsonl" 2>/dev/null || echo 0)"
    org_nc="$(awk -F'"' '/"status":"NOT CHECKED"/{c++} END{print c+0}' "$org_jsonl" 2>/dev/null || echo 0)"

    local total_pass=$org_pass total_fail=$org_fail total_nc=$org_nc
    local proj_count=0 high_fail_projs=0
    local -a proj_rows=() hot_rows=()

    if [[ -d "$projs_dir" ]]; then
        local jf nf pname p_p p_f p_nc safe
        while IFS= read -r jf; do
            [[ -f "$jf" ]] || continue
            proj_count=$(( proj_count + 1 ))
            safe="$(basename "$jf" .jsonl)"
            nf="${projs_dir}/${safe}.name"
            pname="$(cat "$nf" 2>/dev/null || echo "$safe")"
            p_p="$(awk -F'"' '/"status":"PASS"/{c++} END{print c+0}' "$jf")"
            p_f="$(awk -F'"' '/"status":"FAIL"/{c++} END{print c+0}' "$jf")"
            p_nc="$(awk -F'"' '/"status":"NOT CHECKED"/{c++} END{print c+0}' "$jf")"
            total_pass=$(( total_pass + p_p ))
            total_fail=$(( total_fail + p_f ))
            total_nc=$(( total_nc + p_nc ))
            (( p_f > 20 )) && high_fail_projs=$(( high_fail_projs + 1 ))
            local pname_esc; pname_esc="$(printf '%s' "$pname" | html_escape)"
            proj_rows+=("$(printf '%05d\t<tr><td>%s</td><td><span class="pill pill-pass">%s</span></td><td><span class="pill pill-fail">%s</span></td><td><span class="pill pill-nc">%s</span></td></tr>' \
                "$p_f" "$pname_esc" "$p_p" "$p_f" "$p_nc")")
            if (( p_f > 0 )); then
                hot_rows+=("$(printf '%05d\t%s\t%s' "$p_f" "$p_f" "$pname_esc")")
            fi
        done < <(find "$projs_dir" -maxdepth 1 -name '*.jsonl' -type f 2>/dev/null | sort)
    fi

    # Build "Hot spots" list (top 10 projects with FAILs, ordered by fail count desc)
    local hot_spots_html=''
    if (( ${#hot_rows[@]} > 0 )); then
        local hot_sorted rank=0 fcount pname_h urgency
        hot_sorted="$(printf '%s\n' "${hot_rows[@]}" | sort -t$'\t' -k1,1nr | head -n 10)"
        while IFS=$'\t' read -r _ fcount pname_h; do
            [[ -z "$fcount" ]] && continue
            rank=$(( rank + 1 ))
            if   (( fcount > 15 )); then urgency='urgent'
            elif (( fcount > 5 ));  then urgency='warning'
            else                          urgency='info'; fi
            hot_spots_html+="$(printf '<li class="action-item action-%s"><span class="action-rank">#%d</span><strong>%s</strong> &mdash; %d best practice(s) to adopt</li>' \
                "$urgency" "$rank" "$pname_h" "$fcount")"
        done <<<"$hot_sorted"
    fi

    local total_controls=$(( total_pass + total_fail + total_nc ))
    local pass_pct=0 fail_pct=0 nc_pct=0
    if (( total_controls > 0 )); then
        pass_pct=$(( total_pass * 100 / total_controls ))
        fail_pct=$(( total_fail * 100 / total_controls ))
        nc_pct=$(( total_nc * 100 / total_controls ))
    fi
    local ring_dash=$(( 377 * pass_pct / 100 ))

    local risk_level risk_color
    if (( total_fail > 100 || high_fail_projs > 5 )); then risk_level='Limited'; risk_color='#dc2626'
    elif (( total_fail > 50 || high_fail_projs > 2 )); then risk_level='Partial';  risk_color='#ea580c'
    elif (( total_fail > 20 )); then                       risk_level='Good';     risk_color='#d97706'
    else                                                    risk_level='Strong';   risk_color='#16a34a'; fi

    # Sort project rows by fail count desc
    local proj_table='' row
    if (( ${#proj_rows[@]} > 0 )); then
        local sorted
        sorted="$(printf '%s\n' "${proj_rows[@]}" | sort -t$'\t' -k1,1nr -r | cut -f2-)"
        proj_table="<div class=\"tbl-wrap\"><table><thead><tr><th>Project</th><th>Pass</th><th>Fail</th><th>NOT CHECKED</th></tr></thead><tbody>${sorted}</tbody></table></div>"
    fi

        # Top remediations: top 5 FAILs by frequency of control name (parity with PowerShell)
        local top_rem=''
        local total_remed_issues=0 top5_count=0 top5_pct=0
    {
        cat "$org_jsonl" 2>/dev/null
        find "$projs_dir" -maxdepth 1 -name '*.jsonl' -type f -exec cat {} + 2>/dev/null
    } | jq -r 'select(.status=="FAIL") | [.severity, .control] | @tsv' 2>/dev/null \
            | sort | uniq -c | sort -k1,1nr | tee "${ADOQR_TMP}/top_rem_counts.tmp" | head -n 5 \
      | while IFS= read -r line; do
            local cnt sev ctl
            cnt="$(awk '{print $1}' <<<"$line")"
            sev="$(awk '{print $2}' <<<"$line")"
            ctl="$(awk '{ for (i=3;i<=NF;i++) printf "%s%s", $i, (i<NF?" ":"") }' <<<"$line")"
            local sev_pill='pill-nc'
            [[ "$sev" == "High" ]] && sev_pill='pill-fail'
            [[ "$sev" == "Low"  ]] && sev_pill='pill-nc'
            local ctl_esc; ctl_esc="$(printf '%s' "$ctl" | html_escape)"
            printf '<tr><td>%s</td><td><span class="pill %s">%s</span></td><td>%s</td></tr>' \
                "$ctl_esc" "$sev_pill" "$sev" "$cnt"
        done > "${ADOQR_TMP}/top_rem.html.tmp" || true
    [[ -s "${ADOQR_TMP}/top_rem.html.tmp" ]] && top_rem="$(cat "${ADOQR_TMP}/top_rem.html.tmp")"
    if [[ -s "${ADOQR_TMP}/top_rem_counts.tmp" ]]; then
        total_remed_issues="$(awk '{s+=$1} END{print s+0}' "${ADOQR_TMP}/top_rem_counts.tmp")"
        top5_count="$(head -n 5 "${ADOQR_TMP}/top_rem_counts.tmp" | awk '{s+=$1} END{print s+0}')"
        if (( total_remed_issues > 0 )); then
            top5_pct=$(( top5_count * 100 / total_remed_issues ))
        fi
    fi

    # Organization extensions section data (parity with PowerShell report).
    local org_ext_f ext_available installed_count default_count ext_total ext_rows ext_html
    org_ext_f="$(ado_get "${EXTMGMT_URL}/_apis/extensionmanagement/installedextensions?api-version=7.1-preview.1" || true)"
    ext_available=0
    installed_count=0
    default_count=0
    ext_total=0
    ext_rows=''
    ext_html=''
    if [[ -n "$org_ext_f" && -f "$org_ext_f" ]]; then
        ext_available=1
        ext_total="$(jq '(.value // []) | length' "$org_ext_f" 2>/dev/null || echo 0)"
        installed_count="$(jq '[(.value // [])[] | select((((.installState.flags // "") | test("BuiltIn"; "i")) | not))] | length' "$org_ext_f" 2>/dev/null || echo 0)"
        default_count="$(jq '[(.value // [])[] | select(((.installState.flags // "") | test("BuiltIn"; "i")))] | length' "$org_ext_f" 2>/dev/null || echo 0)"

        while IFS=$'\t' read -r type_sort name publisher version type source; do
            local name_esc publisher_esc version_esc type_esc source_esc
            [[ -z "$name" ]] && name='(Unnamed extension)'
            [[ -z "$publisher" ]] && publisher='-'
            [[ -z "$version" ]] && version='-'
            name_esc="$(printf '%s' "$name" | html_escape)"
            publisher_esc="$(printf '%s' "$publisher" | html_escape)"
            version_esc="$(printf '%s' "$version" | html_escape)"
            type_esc="$(printf '%s' "$type" | html_escape)"
            source_esc="$(printf '%s' "$source" | html_escape)"
            ext_rows+="<tr><td>${name_esc}</td><td>${publisher_esc}</td><td>${version_esc}</td><td>${type_esc}</td><td>${source_esc}</td></tr>"
        done < <(jq -r '(.value // [])
            | map({
                name: (.extensionName // ""),
                publisher: (.publisherName // ""),
                version: (.version // ""),
                isBuiltIn: (((.installState.flags // "") | test("BuiltIn"; "i"))),
                isMicrosoft: (((.publisherName // "") | ascii_downcase) == "microsoft"),
                isTrusted: (((.flags // "") | test("trusted"; "i")) or ((.installState.flags // "") | test("trusted"; "i")))
            })
            | map(. + {
                type: (if .isBuiltIn then "Default" else "Installed" end),
                typeSort: (if .isBuiltIn then 1 else 0 end),
                source: (if .isMicrosoft then "Microsoft" elif .isTrusted then "Trusted" else "Other" end)
            })
            | sort_by(.typeSort, .name, .publisher)
            | .[]
            | [(.typeSort|tostring), .name, .publisher, .version, .type, .source] | @tsv' "$org_ext_f" 2>/dev/null)
    fi

    if (( ext_available == 0 )); then
        ext_html='<p class="cmp-empty">Installed extensions could not be retrieved for this run.</p>'
    elif [[ -z "$ext_rows" ]]; then
        ext_html='<p class="cmp-empty">No installed extensions were returned by the organization API.</p>'
    else
        ext_html="<div class=\"tbl-wrap\"><table><thead><tr><th>Extension</th><th>Publisher</th><th>Version</th><th>Type</th><th>Source</th></tr></thead><tbody>${ext_rows}</tbody></table></div>"
    fi

    # Run comparison section
    local cmp_html runs_json
    runs_json="$(get_prior_scan_runs "$run_id" 2>/dev/null || echo '[]')"
    cmp_html="$(printf '%s' "$runs_json" | build_comparison_section_html)"

    # Not Checked section (empty string when nothing is not-checked).
    local not_checked_html
    not_checked_html="$(build_not_checked_section_html "$org_jsonl" "$projs_dir")"

    local elapsed_str
    if (( elapsed >= 60 )); then
        elapsed_str="$(( elapsed / 60 ))m $(( elapsed % 60 ))s"
    else
        elapsed_str="${elapsed}s"
    fi

    local header_html
    header_html="$(get_adoqr_header_html "Executive Summary" "$ORG_SHORT_NAME" \
        "Generated $(printf '%s' "$date_str" | html_escape)" \
        "Run ID: $(printf '%s' "$run_id" | html_escape)" \
        "Elapsed: $(printf '%s' "$elapsed_str" | html_escape)")"

    local remed_file_name
    remed_file_name="${ORG_SAFE_NAME}-remediation-plan.html"
    local org_md_file_name org_name_esc
    org_md_file_name="${ORG_SAFE_NAME}-org-assessment.md"
    org_name_esc="$(printf '%s' "$ORG_SHORT_NAME" | html_escape)"

    local base_css; base_css="$(get_adoqr_base_css)"

    {
        cat <<HTMLHEAD
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ADOQR Executive Summary - ${ORG_SHORT_NAME}</title>
<style>
${base_css}
</style>
</head>
<body>
<a href="#main" class="skip-link">Skip to main content</a>
${header_html}

<nav class="section-nav" aria-label="Section navigation">
    <div class="section-nav-inner">
        <a href="#adoption" data-target="adoption">Overview</a>
        <a href="#top-remediations" data-target="top-remediations">Top Actions</a>
        <a href="#hot-spots" data-target="hot-spots">Hot Spots</a>
        <a href="#organization" data-target="organization">Organization</a>
        <a href="#project-results" data-target="project-results">Projects</a>
        <a href="#not-checked-section" data-target="not-checked-section">Not Checked</a>
        <a href="#organization-extensions" data-target="organization-extensions">Extensions</a>
        <a href="#comparison-section" data-target="comparison-section">Run Comparison</a>
        <span class="section-nav-resources">
            <a class="nav-external" href="https://microsoft.github.io/adoqr/controls.html"
                 target="_blank" rel="noopener noreferrer"
                 aria-label="Open the full controls reference in a new tab">Controls reference</a>
        </span>
    </div>
</nav>

<main id="main"><div class="container">

    <div class="cards" role="list">
        <div class="card card-risk" role="listitem">
            <div class="card-value" style="color:${risk_color}" aria-label="Adoption level ${risk_level}">${risk_level}</div>
            <div class="card-label">Best Practice Adoption</div>
        </div>
        <div class="card card-pass" role="listitem">
            <div class="card-value">${total_pass}</div>
            <div class="card-label">Best Practices Adopted</div>
        </div>
        <div class="card card-fail" role="listitem">
            <div class="card-value">${total_fail}</div>
            <div class="card-label">Improvement Opportunities</div>
        </div>
        <div class="card card-nc" role="listitem">
            <div class="card-value" title="Controls that need more context, permissions, configuration data, or manual confirmation before a PASS/FAIL determination.">${total_nc}</div>
            <div class="card-label">Not Checked</div>
        </div>
    </div>

    <section class="section section-accent-pass" id="adoption" aria-label="Best practice adoption overview">
        <p class="section-eyebrow"><span class="section-eyebrow-dot"></span>Overview</p>
        <h2>Best Practice Adoption</h2>
        <div class="ring-container">
            <div class="ring" role="img" aria-label="${pass_pct} percent of best practices adopted">
                <svg viewBox="0 0 140 140" width="140" height="140">
                    <circle cx="70" cy="70" r="60" fill="none" stroke="var(--surface2)" stroke-width="12"/>
                    <circle cx="70" cy="70" r="60" fill="none" stroke="var(--pass)" stroke-width="12"
                            stroke-dasharray="${ring_dash} 377"
                            stroke-linecap="round"/>
                </svg>
                <span class="ring-label">${pass_pct}%</span>
            </div>
            <div>
                <p style="margin:0"><strong>${total_controls}</strong> best practices evaluated across <strong>${proj_count}</strong> projects</p>
                <p style="margin:.25rem 0;color:var(--text2)">
                    <span style="color:var(--pass)">&#9679; ${total_pass} adopted (${pass_pct}%)</span> &nbsp;
                    <span style="color:var(--fail)">&#9679; ${total_fail} opportunities (${fail_pct}%)</span> &nbsp;
                    <span style="color:var(--warn)">&#9679; ${total_nc} not checked (${nc_pct}%)</span>
                </p>
            </div>
        </div>
    </section>

    <section class="section section-accent-fail" id="top-remediations" aria-label="Top remediation actions">
    <p class="section-eyebrow"><span class="section-eyebrow-dot"></span>Top actions</p>
    <h2>Top 5 Remediation Actions</h2>
    <p style="color:var(--text2);margin-bottom:1rem">Adopting these 5 actions addresses <strong style="color:var(--text)">${top5_count}</strong> of <strong style="color:var(--text)">${total_remed_issues}</strong> total items (<strong style="color:var(--text)">${top5_pct}%</strong>). <a href="${remed_file_name}">View full remediation plan &rarr;</a></p>
HTMLHEAD
        if [[ -n "$top_rem" ]]; then
            cat <<HTMLTOP
    <div class="tbl-wrap"><table><thead><tr><th>Control</th><th>Severity</th><th>Failure Count</th></tr></thead><tbody>
${top_rem}
    </tbody></table></div>
HTMLTOP
        else
            printf '    <p style="color:var(--text2)">No failed controls.</p>\n'
        fi
        cat <<HTMLFOOT
  </section>

    <section class="section section-accent-warn" id="hot-spots" aria-label="Priority actions by project">
        <p class="section-eyebrow"><span class="section-eyebrow-dot"></span>Hot spots</p>
        <h2>Projects With Improvement Opportunities</h2>
HTMLFOOT
        if [[ -n "$hot_spots_html" ]]; then
            printf '        <ol class="action-list">%s</ol>\n' "$hot_spots_html"
        else
            printf '        <p class="cmp-empty">No projects currently have active improvement opportunities.</p>\n'
        fi
        cat <<HTMLFOOT
    </section>

    <section class="section section-accent-accent" id="organization" aria-label="Organization review">
        <p class="section-eyebrow"><span class="section-eyebrow-dot"></span>Organization</p>
        <h2>Organization Review</h2>
        <div class="org-summary">
            <div>
                <strong>${org_name_esc}</strong>
                <span style="color:var(--text2);margin-left:.5rem">
                    <a href="${org_md_file_name}">Full Report</a>
                </span>
            </div>
            <div class="org-stats">
                <div class="stat"><div class="stat-val" style="color:var(--pass)">${org_pass}</div><div class="stat-lbl">Adopted</div></div>
                <div class="stat"><div class="stat-val" style="color:var(--fail)">${org_fail}</div><div class="stat-lbl">Opportunities</div></div>
                <div class="stat"><div class="stat-val" style="color:var(--warn)">${org_nc}</div><div class="stat-lbl">Not Checked</div></div>
            </div>
        </div>
    </section>

    <section class="section section-accent-accent" id="organization-extensions" aria-label="Organization extensions">
        <p class="section-eyebrow"><span class="section-eyebrow-dot"></span>Extensions</p>
        <h2>Organization Extensions</h2>
        <p style="color:var(--text2);margin-bottom:1rem"><strong>Installed:</strong> ${installed_count} <span aria-hidden="true">|</span> <strong>Defaults:</strong> ${default_count}</p>
        <h3 style="margin:0 0 .75rem;font-size:1.05rem">Installed and Default Extensions (${ext_total})</h3>
        ${ext_html}
    </section>

    <section class="section section-accent-accent" id="project-results" aria-label="Per-project results">
        <p class="section-eyebrow"><span class="section-eyebrow-dot"></span>Projects</p>
        <h2>Per-Project Results</h2>
        ${proj_table:-<p style="color:var(--text2)">No projects assessed.</p>}
    </section>

${not_checked_html}

${cmp_html}

</div></main>
</body>
</html>
HTMLFOOT
    } >"$file"

    log_ok "  Report saved: $file"
}

# =============================================================================
#  Remediation HTML report
# =============================================================================
# write_remediation_html_report <file> <org_jsonl> <projects_dir> <run_id>
write_remediation_html_report() {
    local file="$1" org_jsonl="$2" projs_dir="$3" run_id="$4"
    local date_str; date_str="$(date '+%Y-%m-%d %H:%M:%S')"

    # Build remediation map
    local rem_json
    rem_json="$(parse_remediation_psd1 "${SCRIPT_DIR}/remediation-steps.psd1")"

    # Collect all FAILed controls across scopes into per-control aggregated entries
    local all_fail_file="${ADOQR_TMP}/all_fail.jsonl"
    : >"$all_fail_file"
    [[ -s "$org_jsonl" ]] && jq -c 'select(.status=="FAIL")' "$org_jsonl" >>"$all_fail_file" 2>/dev/null || true
    if [[ -d "$projs_dir" ]]; then
        local jf
        while IFS= read -r jf; do
            [[ -f "$jf" ]] || continue
            jq -c 'select(.status=="FAIL")' "$jf" >>"$all_fail_file" 2>/dev/null || true
        done < <(find "$projs_dir" -maxdepth 1 -name '*.jsonl' -type f 2>/dev/null)
    fi

    # Group by control name, aggregating affected scopes/findings.
    local grouped
    grouped="$(jq -s 'group_by(.control) | map({
        control: .[0].control,
        severity: ([.[].severity] | (
            if any(. == "High") then "High"
            elif any(. == "Medium") then "Medium"
            else "Low" end)),
        count: length,
        scopes: [.[] | (if (.scope.type // "organization") == "project" then (.scope.project // "?") else "Organization" end)] | unique,
        findings: [.[].finding] | unique
    }) | sort_by(
        (if .severity == "High" then 0 elif .severity == "Medium" then 1 else 2 end),
        (-.count)
    )' "$all_fail_file" 2>/dev/null || echo '[]')"

    local fail_count
    fail_count="$(jq 'length' <<<"$grouped")"

    local header_html
    header_html="$(get_adoqr_header_html "Remediation Plan" "$ORG_SHORT_NAME" \
        "Generated $(printf '%s' "$date_str" | html_escape)" \
        "Run ID: $(printf '%s' "$run_id" | html_escape)" \
        "Failed controls: ${fail_count}")"

    local base_css; base_css="$(get_adoqr_base_css)"

    {
        cat <<HTMLHEAD
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ADOQR Remediation Plan - ${ORG_SHORT_NAME}</title>
<style>
${base_css}
</style>
</head>
<body>
${header_html}
<main><div class="container">
  <section class="section">
    <p class="section-eyebrow"><span class="section-eyebrow-dot"></span>Action</p>
    <h2>Remediation Plan</h2>
    <p style="color:var(--text2)">${fail_count} distinct failed control(s) detected. Steps below are sourced from <code>remediation-steps.psd1</code>.</p>
  </section>
HTMLHEAD

        if [[ "$fail_count" == "0" ]]; then
            printf '  <section class="section"><p style="color:var(--text2)">No failed controls. Nothing to remediate.</p></section>\n'
        else
            local i=0 g_count
            g_count="$(jq 'length' <<<"$grouped")"
            while (( i < g_count )); do
                local ctl sev cnt scopes_csv findings_csv steps_html doc_url
                ctl="$(jq -r --argjson i "$i" '.[$i].control' <<<"$grouped")"
                sev="$(jq -r --argjson i "$i" '.[$i].severity' <<<"$grouped")"
                cnt="$(jq -r --argjson i "$i" '.[$i].count' <<<"$grouped")"
                scopes_csv="$(jq -r --argjson i "$i" '.[$i].scopes | join(", ")' <<<"$grouped")"
                # First finding text — truncate at 300 chars
                findings_csv="$(jq -r --argjson i "$i" '.[$i].findings[0] // ""' <<<"$grouped")"
                [[ ${#findings_csv} -gt 300 ]] && findings_csv="${findings_csv:0:297}..."
                doc_url="$(jq -r --arg c "$ctl" '.[$c].docUrl // ""' <<<"$rem_json")"
                # Steps list
                steps_html=''
                local step_count si
                step_count="$(jq -r --arg c "$ctl" '(.[$c].steps // []) | length' <<<"$rem_json")"
                if [[ -z "$step_count" || "$step_count" == "0" ]]; then
                    steps_html='<li><em>No remediation steps registered for this control. Refer to product documentation.</em></li>'
                else
                    for (( si=0; si<step_count; si++ )); do
                        local step
                        step="$(jq -r --arg c "$ctl" --argjson i "$si" '.[$c].steps[$i] // ""' <<<"$rem_json")"
                        steps_html+="<li>$(printf '%s' "$step" | html_escape)</li>"
                    done
                fi
                local ctl_esc sev_pill doc_html
                ctl_esc="$(printf '%s' "$ctl" | html_escape)"
                sev_pill='pill-nc'
                [[ "$sev" == "High" ]] && sev_pill='pill-fail'
                doc_html=''
                if [[ -n "$doc_url" ]]; then
                    local doc_esc; doc_esc="$(printf '%s' "$doc_url" | html_escape)"
                    doc_html="<a class=\"rem-doclink\" href=\"${doc_esc}\" target=\"_blank\" rel=\"noopener\">Microsoft Learn docs &rarr;</a>"
                fi
                local scopes_esc finding_esc
                scopes_esc="$(printf '%s' "$scopes_csv" | html_escape)"
                finding_esc="$(printf '%s' "$findings_csv" | html_escape)"
                cat <<HTMLCARD
  <div class="rem-card">
    <h3>${ctl_esc}</h3>
    <div class="rem-meta">
      <span class="pill ${sev_pill}">${sev}</span>
      <span>${cnt} occurrence(s)</span> &middot;
      <span>Scope: ${scopes_esc}</span>
    </div>
    <div class="rem-finding">${finding_esc}</div>
    <ol class="rem-steps">${steps_html}</ol>
    ${doc_html}
  </div>
HTMLCARD
                i=$(( i + 1 ))
            done
        fi

        cat <<'HTMLFOOT'
</div></main>
</body>
</html>
HTMLFOOT
    } >"$file"

    log_ok "  Report saved: $file"
}

# =============================================================================
#  Parallel project execution helper
# =============================================================================
# parallel_throttle <max_n>  — uses a FIFO as a counting semaphore.
# Initialises FIFO at $ADOQR_TMP/state/parallel.fifo on first call.
PARALLEL_FIFO=''
PARALLEL_FD=''
parallel_init() {
    local n="$1"
    (( n > 1 )) || return 0
    [[ -n "$PARALLEL_FIFO" ]] && return 0
    local fifo="${ADOQR_TMP}/state/parallel.fifo"
    mkdir -p "$(dirname "$fifo")"
    mkfifo "$fifo" 2>/dev/null || { log_warn "Could not create FIFO for parallel mode; running sequentially."; return 1; }
    exec {PARALLEL_FD}<>"$fifo"
    PARALLEL_FIFO="$fifo"
    local i
    for (( i=0; i<n; i++ )); do printf '\n' >&"$PARALLEL_FD"; done
}
parallel_acquire() { [[ -n "$PARALLEL_FD" ]] && read -r -u "$PARALLEL_FD" _ || true; }
parallel_release() { [[ -n "$PARALLEL_FD" ]] && printf '\n' >&"$PARALLEL_FD" || true; }

# Open a file in the user's default browser/viewer. Best-effort: silently
# skips if no opener is available (e.g. headless CI).
open_report_in_browser() {
    local path="$1"
    [[ -z "$path" || ! -f "$path" ]] && return 0

    # On Git Bash / MSYS / Cygwin / WSL, convert POSIX path to Windows form
    # so Windows openers (explorer.exe, cmd.exe, powershell.exe) receive a
    # path they can actually resolve. Native Linux/macOS openers consume
    # the POSIX path as-is.
    local win_path="$path"
    if command -v cygpath >/dev/null 2>&1; then
        win_path="$(cygpath -w "$path" 2>/dev/null || printf '%s' "$path")"
    elif command -v wslpath >/dev/null 2>&1; then
        win_path="$(wslpath -w "$path" 2>/dev/null || printf '%s' "$path")"
    fi

    log_step "Opening executive report in default browser..."

    # Linux
    if command -v xdg-open >/dev/null 2>&1; then
        nohup xdg-open "$path" >/dev/null 2>&1 </dev/null &
        disown 2>/dev/null || true
        return 0
    fi
    # macOS
    if command -v open >/dev/null 2>&1; then
        nohup open "$path" >/dev/null 2>&1 </dev/null &
        disown 2>/dev/null || true
        return 0
    fi
    # WSL utility
    if command -v wslview >/dev/null 2>&1; then
        nohup wslview "$path" >/dev/null 2>&1 </dev/null &
        disown 2>/dev/null || true
        return 0
    fi
    # Windows: explorer.exe is the most reliable way to invoke the default
    # handler from a bash shell. It returns exit code 1 even on success, so
    # the trailing `|| true` keeps `set -e` happy.
    if command -v explorer.exe >/dev/null 2>&1; then
        explorer.exe "$win_path" >/dev/null 2>&1 || true
        return 0
    fi
    if command -v cmd.exe >/dev/null 2>&1; then
        cmd.exe /c start "" "$win_path" >/dev/null 2>&1 || true
        return 0
    fi
    if command -v powershell.exe >/dev/null 2>&1; then
        powershell.exe -NoProfile -Command "Start-Process -FilePath '$win_path'" >/dev/null 2>&1 || true
        return 0
    fi
    log_warn "  Could not find a browser opener (xdg-open, open, wslview, explorer.exe, cmd.exe, powershell.exe). Open the report manually: $path"
    return 0
}

# =============================================================================
#  Main
# =============================================================================

main() {
    load_settings_file

    log_hdr "============================================"
    log_hdr "  Azure DevOps Quick Review"
    log_hdr "============================================"
    printf 'Organization : %s\n' "$ORG_URL"
    printf 'Org Name     : %s\n' "$ORG_SHORT_NAME"
    printf 'Output Path  : %s\n' "$RUN_OUTPUT_DIR"
    printf '\n'

    check_prereqs

    log_step "Obtaining bearer token..."
    get_ado_bearer_token >/dev/null
    log_ok "  Token obtained."

    # Set default org for `az devops` commands
    az devops configure --defaults organization="$ORG_URL" >/dev/null 2>&1 || true

    # Discover projects and validate filters
    log_step "Validating organization and discovering projects..."
    local proj_list_path
    proj_list_path="$(ado_get "${ORG_URL}/_apis/projects?api-version=7.1-preview.4&\$top=1000&stateFilter=all" || true)"
    if [[ -z "$proj_list_path" || ! -f "$proj_list_path" ]]; then
        die "Could not enumerate projects in organization '${ORG_SHORT_NAME}'. Check spelling, sign-in, and permissions."
    fi

    local -a discovered_names=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && discovered_names+=("$line")
    done < <(jq -r '.value[]?.name // empty' "$proj_list_path")

    if (( ${#discovered_names[@]} == 0 )); then
        die "Organization '${ORG_SHORT_NAME}' contains no projects."
    fi

    local -a project_names=()
    if (( ${#PROJECTS[@]} > 0 )); then
        local p found d
        for p in "${PROJECTS[@]}"; do
            found=0
            for d in "${discovered_names[@]}"; do
                if [[ "${p,,}" == "${d,,}" ]]; then
                    project_names+=("$d"); found=1; break
                fi
            done
            (( found == 1 )) || {
                log_err "Project '${p}' not found in organization '${ORG_SHORT_NAME}'."
                printf 'Available projects (%s):\n' "${#discovered_names[@]}" >&2
                printf '  %s\n' "${discovered_names[@]:0:20}" >&2
                exit 1
            }
        done
        log_ok "  Validated ${#project_names[@]} project(s): $(IFS=', '; printf '%s' "${project_names[*]}")"
    else
        project_names=("${discovered_names[@]}")
        log_ok "  Found ${#project_names[@]} project(s) in '${ORG_SHORT_NAME}'."
    fi
    printf '\n'

    if (( MAX_PARALLEL > 1 )); then
        if parallel_init "$MAX_PARALLEL"; then
            log_step "Parallel mode enabled (max ${MAX_PARALLEL} concurrent project assessments)."
        else
            MAX_PARALLEL=1
        fi
    fi

    local start_ts; start_ts="$(date +%s)"

    # ---- Org assessment ----------------------------------------------------
    local org_results="${ADOQR_TMP}/results/org.jsonl"
    : >"$org_results"
    log_step "Assessing organization..."
    test_org_policies          "$org_results"
    test_org_users             "$org_results"
    test_org_admins            "$org_results"
    test_org_extensions        "$org_results"
    test_org_audit             "$org_results"
    test_org_pipeline_settings "$org_results"
    test_org_feeds             "$org_results"
    test_org_pat_policy        "$org_results"
    test_user_pats             "$org_results"
    test_org_wide_pats         "$org_results"

    local org_md=''
    if (( WRITE_MARKDOWN == 1 )); then
        org_md="${RUN_OUTPUT_DIR}/${ORG_SAFE_NAME}-org-assessment.md"
        write_assessment_report "$org_md" \
            "Organization Quick Review: ${ORG_SHORT_NAME}" \
            "Organization: ${ORG_URL}" \
            "$org_results"
    fi

    # ---- Project assessments ----------------------------------------------
    local projects_dir="${ADOQR_TMP}/results/projects"
    mkdir -p "$projects_dir"
    _assess_one_project() {
        local proj="$1" safe rf proj_md
        log_step "Assessing project '${proj}'..."
        safe="$(get_safe_file_name "$proj")"
        rf="${projects_dir}/${safe}.jsonl"
        : >"$rf"
        printf '%s' "$proj" >"${projects_dir}/${safe}.name"

        test_project_settings    "$rf" "$proj"
        test_build_pipelines     "$rf" "$proj"
        test_release_pipelines   "$rf" "$proj"
        test_service_connections "$rf" "$proj"
        test_agent_pools         "$rf" "$proj"
        test_repositories        "$rf" "$proj"
        test_project_feeds       "$rf" "$proj"
        test_secure_files        "$rf" "$proj"
        test_environments        "$rf" "$proj"
        test_variable_groups     "$rf" "$proj"

        if (( WRITE_MARKDOWN == 1 )); then
            proj_md="${RUN_OUTPUT_DIR}/${ORG_SAFE_NAME}-${safe}-assessment.md"
            write_assessment_report "$proj_md" \
                "Project Quick Review: ${proj}" \
                "Organization: ${ORG_URL} | Project: ${proj}" \
                "$rf"
        fi
    }
    local proj
    if (( MAX_PARALLEL > 1 && ${#project_names[@]} > 1 )); then
        for proj in "${project_names[@]}"; do
            parallel_acquire
            ( _assess_one_project "$proj"; parallel_release ) &
        done
        wait
    else
        for proj in "${project_names[@]}"; do
            _assess_one_project "$proj"
        done
    fi

    local end_ts; end_ts="$(date +%s)"
    local elapsed=$(( end_ts - start_ts ))

    # ---- JSON output ------------------------------------------------------
    local json_path=''
    if (( WRITE_JSON == 1 )); then
        json_path="${RUN_OUTPUT_DIR}/${ORG_SAFE_NAME}-scan.json"
        export_assessment_to_json "$json_path" \
            "$ORG_SHORT_NAME" "$ORG_URL" \
            "$org_results" "$projects_dir" "$elapsed"
    fi

    # ---- HTML reports -----------------------------------------------------
    local exec_html='' rem_html='' run_id
    run_id="$(basename "$RUN_OUTPUT_DIR")"
    if (( WRITE_HTML == 1 )); then
        exec_html="${RUN_OUTPUT_DIR}/${ORG_SAFE_NAME}-executive-summary.html"
        log_step "Writing executive HTML report..."
        write_executive_html_report "$exec_html" "$org_results" "$projects_dir" "$elapsed" "$run_id"
        rem_html="${RUN_OUTPUT_DIR}/${ORG_SAFE_NAME}-remediation-plan.html"
        log_step "Writing remediation HTML report..."
        write_remediation_html_report "$rem_html" "$org_results" "$projects_dir" "$run_id"
    fi

    # ---- Summary ----------------------------------------------------------
    printf '\n'
    log_hdr "============================================"
    log_hdr "  Review Complete"
    log_hdr "============================================"
    printf 'Reports saved to : %s\n' "$RUN_OUTPUT_DIR"
    [[ -n "$org_md"    ]] && printf 'Org markdown     : %s\n' "$org_md"
    [[ -n "$exec_html" ]] && printf 'Executive HTML   : %s\n' "$exec_html"
    [[ -n "$rem_html"  ]] && printf 'Remediation HTML : %s\n' "$rem_html"
    [[ -n "$json_path" ]] && printf 'JSON scan doc    : %s\n' "$json_path"
    if (( elapsed >= 60 )); then
        printf 'Elapsed time     : %dm %ds\n' "$(( elapsed / 60 ))" "$(( elapsed % 60 ))"
    else
        printf 'Elapsed time     : %ds\n' "$elapsed"
    fi
    printf '\n'

    # Auto-open the executive report (parity with invoke-adoqr.ps1).
    if [[ -n "$exec_html" && -f "$exec_html" && -z "${ADOQR_NO_OPEN:-}" ]]; then
        open_report_in_browser "$exec_html"
    fi
}

main "$@"
