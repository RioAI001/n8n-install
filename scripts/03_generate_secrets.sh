#!/bin/bash
# =============================================================================
# 03_generate_secrets.sh - Secret and configuration generator
# =============================================================================
# Generates secure passwords, JWT secrets, API keys, and encryption keys for
# all services. Creates the .env file from .env.example template.
#
# Features:
#   - Generates cryptographically secure random values (passwords, secrets, keys)
#   - Creates bcrypt hashes for Caddy basic auth using `caddy hash-password`
#   - Preserves existing user-provided values in .env on re-run
#   - Supports --update flag to add new variables without regenerating existing
#   - Prompts for domain name and Let's Encrypt email
#
# Secret types: password (alphanum), secret (base64), hex, api_key, jwt
#
# Usage: bash scripts/03_generate_secrets.sh [--update]
# =============================================================================

set -e

# Source the utilities file and initialize paths
source "$(dirname "$0")/utils.sh"
init_paths

# Setup cleanup for temporary files
TEMP_FILES=()
cleanup_temp_files() {
    for f in "${TEMP_FILES[@]}"; do
        rm -f "$f" 2>/dev/null
    done
}
trap cleanup_temp_files EXIT

# Check for openssl
require_command "openssl" "Please ensure openssl is installed and available in your PATH."
require_command "python3" "Python 3 is required to generate bcrypt hashes."

# --- Configuration ---
TEMPLATE_FILE="$PROJECT_ROOT/.env.example"
OUTPUT_FILE="$PROJECT_ROOT/.env"
ROUTING_MAP_FILE="$PROJECT_ROOT/traefik/routing-map.yml"

render_template_file() {
    local src="$1"
    local dest="$2"

    require_file "$src" "Template missing: $src"
    mkdir -p "$(dirname "$dest")"
    cp "$src" "$dest"
}

ensure_local_ca() {
    local cert_path="$LOCAL_CA_CERT"
    local key_path="$LOCAL_CA_KEY"

    [[ "$cert_path" != /* ]] && cert_path="$PROJECT_ROOT/$cert_path"
    [[ "$key_path" != /* ]] && key_path="$PROJECT_ROOT/$key_path"

    mkdir -p "$(dirname "$cert_path")" "$(dirname "$key_path")"

    if [[ -s "$cert_path" && -s "$key_path" ]]; then
        log_info "Local CA assets already present; skipping generation."
        LOCAL_CA_CERT_RESOLVED="$cert_path"
        LOCAL_CA_KEY_RESOLVED="$key_path"
        return
    fi

    if command -v mkcert >/dev/null 2>&1; then
        log_info "Generating local CA and wildcard certificate with mkcert for $WILDCARD_DOMAIN"
        mkcert -install
        mkcert -key-file "$key_path" -cert-file "$cert_path" "$WILDCARD_DOMAIN"
    else
        log_warning "mkcert not found. Falling back to OpenSSL self-signed CA for $WILDCARD_DOMAIN"
        openssl req -x509 -nodes -days 3650 \
          -newkey rsa:4096 \
          -keyout "$key_path" \
          -out "$cert_path" \
          -subj "/CN=${WILDCARD_DOMAIN}"
    fi

    chmod 600 "$key_path" "$cert_path" 2>/dev/null || true
    LOCAL_CA_CERT_RESOLVED="$cert_path"
    LOCAL_CA_KEY_RESOLVED="$key_path"
}

print_local_ca_trust_instructions() {
    log_box "Local TLS enabled. Trust the generated CA to avoid browser warnings."
    echo ""
    local cert_hint="${LOCAL_CA_CERT_RESOLVED:-$LOCAL_CA_CERT}"
    echo "Ubuntu/Debian: sudo cp ${cert_hint} /usr/local/share/ca-certificates/localai.crt && sudo update-ca-certificates"
    echo "macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${cert_hint}"
    echo "Windows (PowerShell admin): certutil -addstore Root ${cert_hint}"
}

ensure_traefik_acme_storage() {
    local storage_path="${TRAEFIK_ACME_STORAGE:-traefik/acme.json}"

    [[ "$storage_path" != /* ]] && storage_path="$PROJECT_ROOT/$storage_path"
    mkdir -p "$(dirname "$storage_path")"
    touch "$storage_path"
    chmod 600 "$storage_path" 2>/dev/null || true
    log_info "Ensured Traefik ACME storage at $storage_path"
}

# START generate_proxy_configs

generate_proxy_configs() {
    local proxy_choice="$1"

    mkdir -p "$PROJECT_ROOT/traefik"

    if [[ ! -f "$ROUTING_MAP_FILE" ]]; then
        log_error "Routing map missing at $ROUTING_MAP_FILE."
        exit 1
    fi

    if [[ "$proxy_choice" == "traefik" ]]; then
        ensure_traefik_acme_storage
    fi

    python3 - "$ROUTING_MAP_FILE" "$PROJECT_ROOT/Caddyfile" "$PROJECT_ROOT/traefik/traefik.dynamic.yml" "$PROJECT_ROOT/traefik/traefik.yml" <<'PY'
import json
import sys
from pathlib import Path

map_path = Path(sys.argv[1])
caddy_out = Path(sys.argv[2])
traefik_dynamic_out = Path(sys.argv[3])
traefik_static_out = Path(sys.argv[4])

with map_path.open() as f:
    routes = json.load(f)


def yaml_dump(node, indent=0):
    spaces = ' ' * indent
    if isinstance(node, dict):
        lines = []
        for key, value in node.items():
            if value is None:
                continue
            if isinstance(value, (dict, list)):
                lines.append(f"{spaces}{key}:")
                lines.append(yaml_dump(value, indent + 2))
            else:
                lines.append(f"{spaces}{key}: {json.dumps(value)}")
        return "\n".join(lines)
    if isinstance(node, list):
        lines = []
        for item in node:
            if isinstance(item, (dict, list)):
                lines.append(f"{spaces}-")
                lines.append(yaml_dump(item, indent + 2))
            else:
                lines.append(f"{spaces}- {json.dumps(item)}")
        return "\n".join(lines)
    return f"{spaces}{json.dumps(node)}"


http_middlewares = {}
http_routers = {}
http_services = {}
tcp_routers = {}
tcp_services = {}


def add_basic_auth(entry):
    name = f"auth-{entry['name']}"
    http_middlewares[name] = {
        "basicAuth": {
            "users": [f"${{{entry['user_env']}:?}}:${{{entry['hash_env']}:?}}"]
        }
    }
    return name


for entry in routes:
    protocol = entry.get("protocol", "http")

    if protocol == "tcp":
        service_name = f"{entry['name']}-svc"
        tcp_services[service_name] = {
            "loadBalancer": {
                "servers": [
                    {
                        "address": entry["address"],
                    }
                ]
            }
        }
        tcp_routers[entry["name"]] = {
            "rule": f"HostSNI(`${{{entry['host_var']}}}`)",
            "entryPoints": ["bolt"],
            "service": service_name,
            "tls": {
                "passthrough": bool(entry.get("tls_passthrough", False))
            },
        }
        continue

    service_name = f"{entry['name']}-svc"
    http_services[service_name] = {
        "loadBalancer": {
            "servers": [
                {
                    "url": entry["url"],
                }
            ]
        }
    }

    middlewares = []
    if entry.get("auth") == "basic":
        middlewares.append(add_basic_auth(entry))
    if entry.get("type") == "searxng":
        middlewares.append("searxng-headers")

    router_def = {
        "rule": f"Host(`${{{entry['host_var']}}}`)",
        "entryPoints": ["websecure"],
        "service": service_name,
        "tls": {"certResolver": "${TRAEFIK_CERT_RESOLVER:-acme}"},
    }
    if middlewares:
        router_def["middlewares"] = middlewares

    http_routers[entry["name"]] = router_def


if any(entry.get("type") == "searxng" for entry in routes):
    http_middlewares["searxng-headers"] = {
        "headers": {
            "customResponseHeaders": {
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "accelerometer=(),camera=(),geolocation=(),gyroscope=(),magnetometer=(),microphone=(),payment=(),usb=()",
            }
        }
    }


traefik_dynamic = {}
if http_routers:
    http_block = {
        "routers": http_routers,
        "services": http_services,
    }
    if http_middlewares:
        http_block["middlewares"] = http_middlewares
    traefik_dynamic["http"] = http_block

if tcp_routers:
    traefik_dynamic["tcp"] = {
        "routers": tcp_routers,
        "services": tcp_services,
    }

traefik_dynamic_out.write_text(
    "# Generated from traefik/routing-map.yml\n" + yaml_dump(traefik_dynamic) + "\n",
    encoding="utf-8",
)

traefik_static_out.write_text(
    "# Generated static config for Traefik\n"
    "global:\n  checkNewVersion: false\n  sendAnonymousUsage: false\n\n"
    "log:\n  level: INFO\n\n"
    "accessLog: {}\n\n"
    "entryPoints:\n  web:\n    address: \":80\"\n  websecure:\n    address: \":443\"\n  bolt:\n    address: \":7687\"\n\n"
    "providers:\n  docker:\n    exposedByDefault: false\n  file:\n    filename: /etc/traefik/traefik.dynamic.yml\n    watch: true\n\n"
    "certificatesResolvers:\n  acme:\n    acme:\n      email: \"${ACME_EMAIL:-}\"\n      storage: \"/acme/acme.json\"\n      httpChallenge:\n        entryPoint: web\n\n"
    "serversTransport:\n  insecureSkipVerify: true\n",
    encoding="utf-8",
)


caddy_lines = [
    "{",
    "    email {$LETSENCRYPT_EMAIL}",
    "}",
    "",
]


def caddy_host(var):
    return "{" + "$" + var + "}"


for entry in routes:
    protocol = entry.get("protocol", "http")

    if entry.get("type") == "searxng":
        host = caddy_host(entry["host_var"])
        user_placeholder = "{" + "$" + entry["user_env"] + "}"
        hash_placeholder = "{" + "$" + entry["hash_env"] + "}"
        searx_block = """
{host} {{
    @protected not remote_ip 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10

    basic_auth @protected {{
        {user} {hash}
    }}

    encode zstd gzip

    @api {{
        path /config
        path /healthz
        path /stats/errors
        path /stats/checker
    }}
    @search {{
        path /search
    }}
    @imageproxy {{
        path /image_proxy
    }}
    @static {{
        path /static/*
    }}

    header {{
        Content-Security-Policy "upgrade-insecure-requests; default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self' https://github.com/searxng/searxng/issues/new; font-src 'self'; frame-ancestors 'self'; base-uri 'self'; connect-src 'self' https://overpass-api.de; img-src * data:; frame-src https://www.youtube-nocookie.com https://player.vimeo.com https://www.dailymotion.com https://www.deezer.com https://www.mixcloud.com https://w.soundcloud.com https://embed.spotify.com;"
        Permissions-Policy "accelerometer=(),camera=(),geolocation=(),gyroscope=(),magnetometer=(),microphone=(),payment=(),usb=()"
        Referrer-Policy "no-referrer"
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options "nosniff"
        X-Robots-Tag "noindex, noarchive, nofollow"
        -Server
    }}

    header @api {{
        Access-Control-Allow-Methods "GET, OPTIONS"
        Access-Control-Allow-Origin "*"
    }}

    route {{
        header Cache-Control "max-age=0, no-store"
        header @search Cache-Control "max-age=5, private"
        header @imageproxy Cache-Control "max-age=604800, public"
        header @static Cache-Control "max-age=31536000, public, immutable"
    }}

    reverse_proxy searxng:8080 {{
        header_up X-Forwarded-Port {{http.request.port}}
        header_up X-Real-IP {{http.request.remote.host}}
        header_up Connection "close"
    }}
}}
""".format(host=host, user=user_placeholder, hash=hash_placeholder)
        caddy_lines.append(searx_block.strip("\n"))
        caddy_lines.append("")
        continue

    if protocol == "tcp":
        host = caddy_host(entry["host_var"])
        caddy_lines.append(f"https://{host}:7687 {{")
        caddy_lines.append(f"    reverse_proxy {entry['address']}")
        caddy_lines.append("}")
        caddy_lines.append("")
        continue

    host = caddy_host(entry["host_var"])
    caddy_lines.append(f"{host} {{")

    if entry.get("auth") == "basic":
        caddy_lines.append("    basic_auth {")
        caddy_lines.append(f"        {{${entry['user_env']}}} {{${entry['hash_env']}}}")
        caddy_lines.append("    }")

    caddy_lines.append(f"    reverse_proxy {entry['url']}")
    caddy_lines.append("}")
    caddy_lines.append("")


caddy_lines.append("import /etc/caddy/addons/*.conf")

caddy_out.write_text("\n".join(caddy_lines) + "\n", encoding="utf-8")
PY

    REVERSE_PROXY="$proxy_choice"
    require_proxy_config
}

# END generate_proxy_configs

# Variables to generate: varName="type:length"
# Types: password (alphanum), secret (base64), hex, base64, alphanum
declare -A VARS_TO_GENERATE=(
    ["CLICKHOUSE_PASSWORD"]="password:32"
    ["COMFYUI_PASSWORD"]="password:32" # Added ComfyUI basic auth password
    ["DASHBOARD_PASSWORD"]="password:32" # Supabase Dashboard
    ["DIFY_SECRET_KEY"]="secret:64" # Dify application secret key (maps to SECRET_KEY in Dify)
    ["DOCLING_PASSWORD"]="password:32"
    ["ENCRYPTION_KEY"]="hex:64" # Langfuse Encryption Key (32 bytes -> 64 hex chars)
    ["FLOWISE_PASSWORD"]="password:32"
    ["GRAFANA_ADMIN_PASSWORD"]="password:32"
    ["JWT_SECRET"]="base64:64" # 48 bytes -> 64 chars
    ["LANGFUSE_INIT_PROJECT_PUBLIC_KEY"]="langfuse_pk:32"
    ["LANGFUSE_INIT_PROJECT_SECRET_KEY"]="langfuse_sk:32"
    ["LANGFUSE_INIT_USER_PASSWORD"]="password:32"
    ["LANGFUSE_SALT"]="secret:64" # base64 encoded, 48 bytes -> 64 chars
    ["LETTA_SERVER_PASSWORD"]="password:32" # Added Letta server password
    ["LIGHTRAG_API_KEY"]="secret:48"
    ["LIGHTRAG_PASSWORD"]="password:32"
    ["LOGFLARE_PRIVATE_ACCESS_TOKEN"]="fixed:not-in-use" # For supabase-vector, can't be empty
    ["LOGFLARE_PUBLIC_ACCESS_TOKEN"]="fixed:not-in-use" # For supabase-vector, can't be empty
    ["LT_PASSWORD"]="password:32" # Added LibreTranslate basic auth password
    ["MINIO_ROOT_PASSWORD"]="password:32"
    ["N8N_ENCRYPTION_KEY"]="secret:64" # base64 encoded, 48 bytes -> 64 chars
    ["N8N_RUNNERS_AUTH_TOKEN"]="secret:64" # Task runner auth token for n8n v2.0
    ["N8N_USER_MANAGEMENT_JWT_SECRET"]="secret:64" # base64 encoded, 48 bytes -> 64 chars
    ["NEO4J_AUTH_PASSWORD"]="password:32" # Added Neo4j password
    ["NEO4J_AUTH_USERNAME"]="fixed:neo4j" # Added Neo4j username
    ["NEXTAUTH_SECRET"]="secret:64" # base64 encoded, 48 bytes -> 64 chars
    ["PADDLEOCR_PASSWORD"]="password:32" # Added PaddleOCR basic auth password
    ["PG_META_CRYPTO_KEY"]="alphanum:32"
    ["POSTGRES_NON_ROOT_PASSWORD"]="password:32"
    ["POSTGRES_PASSWORD"]="password:32"
    ["PROMETHEUS_PASSWORD"]="password:32" # Added Prometheus password
    ["QDRANT_API_KEY"]="secret:48" # API Key for Qdrant service
    ["RAGAPP_PASSWORD"]="password:32" # Added RAGApp basic auth password
    ["RAGFLOW_ELASTICSEARCH_PASSWORD"]="password:32"
    ["RAGFLOW_MINIO_ROOT_PASSWORD"]="password:32"
    ["RAGFLOW_MYSQL_ROOT_PASSWORD"]="password:32"
    ["RAGFLOW_REDIS_PASSWORD"]="password:32"
    ["SEARXNG_PASSWORD"]="password:32" # Added SearXNG admin password
    ["SECRET_KEY_BASE"]="base64:64" # 48 bytes -> 64 chars
    ["VAULT_ENC_KEY"]="alphanum:32"
    ["WAHA_DASHBOARD_PASSWORD"]="password:32"
    ["WEAVIATE_API_KEY"]="secret:48" # API Key for Weaviate service (36 bytes -> 48 chars base64)
    ["WELCOME_PASSWORD"]="password:32" # Welcome page basic auth password
    ["WHATSAPP_SWAGGER_PASSWORD"]="password:32"
)

# Initialize existing_env_vars and attempt to read .env if it exists
log_info "Initializing environment configuration..."
declare -A existing_env_vars
declare -A generated_values

if [ -f "$OUTPUT_FILE" ]; then
    log_info "Found existing $OUTPUT_FILE. Reading its values to use as defaults and preserve current settings."
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ -n "$line" && ! "$line" =~ ^\s*# && "$line" == *"="* ]]; then
            varName=$(echo "$line" | cut -d'=' -f1 | xargs)
            varValue=$(echo "$line" | cut -d'=' -f2-)
            # Repeatedly unquote "value" or 'value' to get the bare value
            _tempVal="$varValue"
            while true; do
                if [[ "$_tempVal" =~ ^\"(.*)\"$ ]]; then # Check double quotes
                    _tempVal="${BASH_REMATCH[1]}"
                    continue
                fi
                if [[ "$_tempVal" =~ ^\'(.*)\'$ ]]; then # Check single quotes
                    _tempVal="${BASH_REMATCH[1]}"
                    continue
                fi
                break # No more surrounding quotes of these types
            done
            varValue="$_tempVal"
            existing_env_vars["$varName"]="$varValue"
        fi
    done < "$OUTPUT_FILE"
fi

# Pre-populate generated_values with non-empty values from existing_env_vars
for key_from_existing in "${!existing_env_vars[@]}"; do
    if [[ -n "${existing_env_vars[$key_from_existing]}" ]]; then
        generated_values["$key_from_existing"]="${existing_env_vars[$key_from_existing]}"
    fi
done

require_whiptail

log_subheader "Proxy and TLS Selection"
DEFAULT_PROXY="${generated_values[REVERSE_PROXY]:-${existing_env_vars[REVERSE_PROXY]:-caddy}}"
DEFAULT_TLS_MODE="${generated_values[TLS_MODE]:-${existing_env_vars[TLS_MODE]:-public}}"

PROXY_CHOICE=$(wt_radiolist "Reverse Proxy" "Choose which proxy to configure." "$DEFAULT_PROXY" \
    "caddy" "Use the existing Caddy-based setup (default)" ON \
    "traefik" "Switch to Traefik (Docker + file providers)" OFF) || exit 1

TLS_MODE_CHOICE=$(wt_radiolist "TLS Mode" "How should certificates be handled?" "$DEFAULT_TLS_MODE" \
    "public" "Public ACME/Let's Encrypt" ON \
    "local" "Local CA + wildcard cert (for homelab domains)" OFF) || exit 1

REVERSE_PROXY="$PROXY_CHOICE"
TLS_MODE="$TLS_MODE_CHOICE"
generated_values["REVERSE_PROXY"]="$PROXY_CHOICE"
generated_values["TLS_MODE"]="$TLS_MODE_CHOICE"

# Prompt for the domain name
log_subheader "Domain Configuration"
DOMAIN="${generated_values[USER_DOMAIN_NAME]:-${existing_env_vars[USER_DOMAIN_NAME]:-}}"

while true; do
    DOMAIN_INPUT=$(wt_input "Primary Domain" "Enter the primary domain name for your services (e.g., example.com or homelab.lan)." "$DOMAIN") || true
    DOMAIN_TO_USE="$DOMAIN_INPUT"

    if [[ -z "$DOMAIN_TO_USE" ]]; then
        wt_msg "Validation" "Domain name cannot be empty."
        continue
    fi

    if [[ "$DOMAIN_TO_USE" =~ [^a-zA-Z0-9.-] ]]; then
        wt_msg "Validation" "Warning: Domain contains potentially invalid characters: '$DOMAIN_TO_USE'"
    fi

    if wt_yesno "Confirm Domain" "Use '$DOMAIN_TO_USE' as the primary domain?" "yes"; then
        DOMAIN="$DOMAIN_TO_USE"
        generated_values["USER_DOMAIN_NAME"]="$DOMAIN"
        log_info "Domain set to '$DOMAIN'. It will be saved in .env."
        break
    fi
done

local_wildcard_default="*.${DOMAIN}"
if [[ -z "${generated_values[WILDCARD_DOMAIN]}" ]]; then
    generated_values["WILDCARD_DOMAIN"]="$local_wildcard_default"
fi

generated_values["LOCAL_CA_CERT"]="${generated_values[LOCAL_CA_CERT]:-${existing_env_vars[LOCAL_CA_CERT]:-certs/local-ca.pem}}"
generated_values["LOCAL_CA_KEY"]="${generated_values[LOCAL_CA_KEY]:-${existing_env_vars[LOCAL_CA_KEY]:-certs/local-ca-key.pem}}"
generated_values["TRAEFIK_ACME_STORAGE"]="${generated_values[TRAEFIK_ACME_STORAGE]:-${existing_env_vars[TRAEFIK_ACME_STORAGE]:-traefik/acme.json}}"
generated_values["TRAEFIK_CERT_RESOLVER"]="${generated_values[TRAEFIK_CERT_RESOLVER]:-${existing_env_vars[TRAEFIK_CERT_RESOLVER]:-acme}}"

if [[ "$TLS_MODE_CHOICE" == "local" ]]; then
    WILDCARD_INPUT=$(wt_input "Wildcard CN" "Wildcard certificate CN" "${generated_values[WILDCARD_DOMAIN]}") || true
    if [[ -n "$WILDCARD_INPUT" ]]; then
        generated_values["WILDCARD_DOMAIN"]="$WILDCARD_INPUT"
    fi
fi

# Prompt for user email (used for ACME + default service logins)
log_subheader "Email Configuration"
DEFAULT_EMAIL="${generated_values[ACME_EMAIL]:-${generated_values[LETSENCRYPT_EMAIL]:-${existing_env_vars[ACME_EMAIL]:-${existing_env_vars[LETSENCRYPT_EMAIL]}}}}"

if [[ -z "$DEFAULT_EMAIL" ]]; then
    wt_msg "Email Required" "Please enter your email address. It will be used for login defaults and Let's Encrypt/ACME registration."
fi

while true; do
    USER_EMAIL=$(wt_input "Email" "Enter your email address." "$DEFAULT_EMAIL") || true

    if [[ -z "$USER_EMAIL" ]]; then
        wt_msg "Validation" "Email cannot be empty."
        continue
    fi

    if [[ ! "$USER_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        wt_msg "Validation" "Warning: Email format appears to be invalid: '$USER_EMAIL'"
    fi
    if wt_yesno "Confirm Email" "Use '$USER_EMAIL' as your email?" "yes"; then
        break
    fi
done

generated_values["ACME_EMAIL"]="$USER_EMAIL"
generated_values["LETSENCRYPT_EMAIL"]="$USER_EMAIL"

if [[ "$TLS_MODE_CHOICE" == "local" ]]; then
    LOCAL_CA_CERT="${generated_values[LOCAL_CA_CERT]}"
    LOCAL_CA_KEY="${generated_values[LOCAL_CA_KEY]}"
    WILDCARD_DOMAIN="${generated_values[WILDCARD_DOMAIN]}"
    ensure_local_ca
    print_local_ca_trust_instructions
fi

log_subheader "Secret Generation"
log_info "Generating secrets and creating .env file..."

# --- Helper Functions ---
# Note: gen_random, gen_password, gen_hex, gen_base64 are now in utils.sh

# Function to update or add a variable to the .env file
# Usage: _update_or_add_env_var "VAR_NAME" "var_value"
_update_or_add_env_var() {
    local var_name="$1"
    local var_value="$2"
    local tmp_env_file

    tmp_env_file=$(mktemp)
    # Ensure temp file is cleaned up if this function exits unexpectedly (though trap in main script should also cover)
    # trap 'rm -f "$tmp_env_file"' EXIT

    if [[ -f "$OUTPUT_FILE" ]]; then
        grep -v -E "^${var_name}=" "$OUTPUT_FILE" > "$tmp_env_file" || true # Allow grep to not find anything
    else
        touch "$tmp_env_file" # Create empty temp if output file doesn't exist yet
    fi

    if [[ -n "$var_value" ]]; then
        echo "${var_name}='$var_value'" >> "$tmp_env_file"
    fi
    mv "$tmp_env_file" "$OUTPUT_FILE"
    # trap - EXIT # Remove specific trap for this temp file if desired, or let main script's trap handle it.
}

# Note: generate_bcrypt_hash() is now in utils.sh

# --- Main Logic ---

if [ ! -f "$TEMPLATE_FILE" ]; then
    log_error "Template file not found at $TEMPLATE_FILE"
    exit 1
fi

# Store user input values (potentially overwriting if user was re-prompted and gave new input)
generated_values["FLOWISE_USERNAME"]="$USER_EMAIL"
generated_values["DASHBOARD_USERNAME"]="$USER_EMAIL"
generated_values["LETSENCRYPT_EMAIL"]="$USER_EMAIL"
generated_values["PROMETHEUS_USERNAME"]="$USER_EMAIL"
generated_values["SEARXNG_USERNAME"]="$USER_EMAIL"
generated_values["LANGFUSE_INIT_USER_EMAIL"]="$USER_EMAIL"
generated_values["WEAVIATE_USERNAME"]="$USER_EMAIL" # Set Weaviate username for Caddy
generated_values["COMFYUI_USERNAME"]="$USER_EMAIL" # Set ComfyUI username for Caddy
generated_values["RAGAPP_USERNAME"]="$USER_EMAIL" # Set RAGApp username for Caddy
generated_values["PADDLEOCR_USERNAME"]="$USER_EMAIL" # Set PaddleOCR username for Caddy
generated_values["LT_USERNAME"]="$USER_EMAIL" # Set LibreTranslate username for Caddy
generated_values["LIGHTRAG_USERNAME"]="$USER_EMAIL" # Set LightRAG username for built-in auth
generated_values["WAHA_DASHBOARD_USERNAME"]="$USER_EMAIL" # WAHA dashboard username default
generated_values["WHATSAPP_SWAGGER_USERNAME"]="$USER_EMAIL" # WAHA swagger username default
generated_values["DOCLING_USERNAME"]="$USER_EMAIL" # Set Docling username for Caddy
generated_values["WELCOME_USERNAME"]="$USER_EMAIL" # Set Welcome page username for Caddy


# Create a temporary file for processing
TMP_ENV_FILE=$(mktemp)
TEMP_FILES+=("$TMP_ENV_FILE")

# Track whether our custom variables were found in the template
declare -A found_vars
found_vars["FLOWISE_USERNAME"]=0
found_vars["DASHBOARD_USERNAME"]=0
found_vars["LETSENCRYPT_EMAIL"]=0
found_vars["ACME_EMAIL"]=0
found_vars["REVERSE_PROXY"]=0
found_vars["TLS_MODE"]=0
found_vars["WILDCARD_DOMAIN"]=0
found_vars["LOCAL_CA_CERT"]=0
found_vars["LOCAL_CA_KEY"]=0
found_vars["TRAEFIK_ACME_STORAGE"]=0
found_vars["TRAEFIK_CERT_RESOLVER"]=0
found_vars["RUN_N8N_IMPORT"]=0
found_vars["PROMETHEUS_USERNAME"]=0
found_vars["SEARXNG_USERNAME"]=0
found_vars["OPENAI_API_KEY"]=0
found_vars["LANGFUSE_INIT_USER_EMAIL"]=0
found_vars["N8N_WORKER_COUNT"]=0
found_vars["WEAVIATE_USERNAME"]=0
found_vars["NEO4J_AUTH_USERNAME"]=0
found_vars["COMFYUI_USERNAME"]=0
found_vars["RAGAPP_USERNAME"]=0
found_vars["PADDLEOCR_USERNAME"]=0
found_vars["DOCLING_USERNAME"]=0
found_vars["LT_USERNAME"]=0
found_vars["LIGHTRAG_USERNAME"]=0
found_vars["WAHA_DASHBOARD_USERNAME"]=0
found_vars["WELCOME_USERNAME"]=0
found_vars["WHATSAPP_SWAGGER_USERNAME"]=0

# Read template, substitute domain, generate initial values
while IFS= read -r line || [[ -n "$line" ]]; do
    # Substitute domain placeholder
    processed_line=$(echo "$line" | sed "s/$DOMAIN_PLACEHOLDER/$DOMAIN/g")

    # Check if it's a variable assignment line (non-empty, not comment, contains '=')
    if [[ -n "$processed_line" && ! "$processed_line" =~ ^\s*# && "$processed_line" == *"="* ]]; then
        varName=$(echo "$processed_line" | cut -d'=' -f1 | xargs) # Trim whitespace
        currentValue=$(echo "$processed_line" | cut -d'=' -f2-)

        # If already have a non-empty value from existing .env or prior generation/user input, use it
        if [[ -n "${generated_values[$varName]}" ]]; then
            processed_line="${varName}=\"${generated_values[$varName]}\""
        # Check if this is one of our user-input derived variables that might not have a value yet
        # (e.g. OPENAI_API_KEY if user left it blank). These are handled by `found_vars` later if needed.
        # Or, if variable needs generation AND is not already populated (or is empty) in generated_values
        elif [[ ${VARS_TO_GENERATE[$varName]+_} && -z "${generated_values[$varName]}" ]]; then
            IFS=':' read -r type length <<< "${VARS_TO_GENERATE[$varName]}"
            newValue=""
            case "$type" in
                password|alphanum) newValue=$(gen_password "$length") ;;
                secret|base64) newValue=$(gen_base64 "$length") ;;
                hex) newValue=$(gen_hex "$length") ;;
                langfuse_pk) newValue="pk-lf-$(gen_hex "$length")" ;;
                langfuse_sk) newValue="sk-lf-$(gen_hex "$length")" ;;
                fixed) newValue="$length" ;; # Handle fixed type
                *) log_warning "Unknown generation type '$type' for $varName" ;;
            esac

            if [[ -n "$newValue" ]]; then
                processed_line="${varName}=\"${newValue}\"" # Quote generated values
                generated_values["$varName"]="$newValue"    # Store newly generated
            else
                # Keep original line structure but ensure value is empty if generation failed
                # but it was in VARS_TO_GENERATE
                processed_line="${varName}=\""
                generated_values["$varName"]="" # Explicitly mark as empty in generated_values
            fi
        # For variables from the template that are not in VARS_TO_GENERATE and not already in generated_values
        # store their template value if it's a direct assignment (not a ${...} substitution)
        # This allows them to be used in later ${VAR} substitutions if they are referenced.
        else
            # This 'else' block is for lines from template not covered by existing values or VARS_TO_GENERATE.
            # Check if it is one of the user input vars - these are handled by found_vars later if not in template.
            is_user_input_var=0 # Reset for each line
    user_input_vars=("FLOWISE_USERNAME" "DASHBOARD_USERNAME" "LETSENCRYPT_EMAIL" "ACME_EMAIL" "REVERSE_PROXY" "TLS_MODE" "WILDCARD_DOMAIN" "LOCAL_CA_CERT" "LOCAL_CA_KEY" "TRAEFIK_ACME_STORAGE" "TRAEFIK_CERT_RESOLVER" "RUN_N8N_IMPORT" "PROMETHEUS_USERNAME" "SEARXNG_USERNAME" "OPENAI_API_KEY" "LANGFUSE_INIT_USER_EMAIL" "N8N_WORKER_COUNT" "WEAVIATE_USERNAME" "NEO4J_AUTH_USERNAME" "COMFYUI_USERNAME" "RAGAPP_USERNAME" "PADDLEOCR_USERNAME" "LT_USERNAME" "LIGHTRAG_USERNAME" "WAHA_DASHBOARD_USERNAME" "WELCOME_USERNAME" "WHATSAPP_SWAGGER_USERNAME")
            for uivar in "${user_input_vars[@]}"; do
                if [[ "$varName" == "$uivar" ]]; then
                    is_user_input_var=1
                    # Mark as found if it's in template, value taken from generated_values if already set or blank
                    found_vars["$varName"]=1 
                    if [[ ${generated_values[$varName]+_} ]]; then # if it was set (even to empty by user)
                        processed_line="${varName}=\"${generated_values[$varName]}\""
                    else # Not set in generated_values, keep template's default if any, or make it empty
                        if [[ "$currentValue" =~ ^\$\{.*\} || -z "$currentValue" ]]; then # if template is ${VAR} or empty
                            processed_line="${varName}=\"\""
                        else # template has a default simple value
                            processed_line="${varName}=\"$currentValue\"" # Use template's default, and quote it
                        fi
                    fi
                    break
                fi
            done

            if [[ $is_user_input_var -eq 0 ]]; then # Not a user input var, not in VARS_TO_GENERATE, not in existing
                trimmed_value=$(echo "$currentValue" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'//")
                if [[ -n "$varName" && -n "$trimmed_value" && "$trimmed_value" != "\${INSTANCE_DOMAIN}" && "$trimmed_value" != "\${SUBDOMAIN_WILDCARD_CERT}" && ! "$trimmed_value" =~ ^\\$\\{ ]]; then # Check for other placeholders
                    # Only store if not already in generated_values and not a placeholder reference
                    if [[ -z "${generated_values[$varName]}" ]]; then
                        generated_values["$varName"]="$trimmed_value"
                    fi
                fi
                # processed_line remains as is (from template, after domain sub) for these cases
            fi
        fi
    fi
    echo "$processed_line" >> "$TMP_ENV_FILE"
done < "$TEMPLATE_FILE"

# Generate placeholder Supabase keys (always generate these)

# Function to create a JWT token
create_jwt() {
    local role=$1
    local jwt_secret=$2
    local now=$(date +%s)
    local exp=$((now + 315360000)) # 10 years from now (seconds)
    
    # Create header (alg=HS256, typ=JWT)
    local header='{"alg":"HS256","typ":"JWT"}'
    # Create payload with role, issued at time, and expiry
    local payload="{\"role\":\"$role\",\"iss\":\"supabase\",\"iat\":$now,\"exp\":$exp}"
    
    # Base64url encode header and payload
    local b64_header=$(echo -n "$header" | base64 -w 0 | tr '/+' '_-' | tr -d '=')
    local b64_payload=$(echo -n "$payload" | base64 -w 0 | tr '/+' '_-' | tr -d '=')
    
    # Create signature
    local signature_input="$b64_header.$b64_payload"
    local signature=$(echo -n "$signature_input" | openssl dgst -sha256 -hmac "$jwt_secret" -binary | base64 -w 0 | tr '/+' '_-' | tr -d '=')
    
    # Combine to form JWT
    echo -n "$b64_header.$b64_payload.$signature" # Use echo -n to avoid trailing newline
}

# Get JWT secret from previously generated values
JWT_SECRET_TO_USE="${generated_values["JWT_SECRET"]}"

if [[ -z "$JWT_SECRET_TO_USE" ]]; then
    # This should ideally have been generated by VARS_TO_GENERATE if it was missing
    # and JWT_SECRET is in VARS_TO_GENERATE. For safety, generate if truly empty.
    log_warning "JWT_SECRET was empty, attempting to generate it now."
    # Assuming JWT_SECRET definition is 'base64:64'
    JWT_SECRET_TO_USE=$(gen_base64 64)
    generated_values["JWT_SECRET"]="$JWT_SECRET_TO_USE"
fi

# Generate the actual JWT tokens using the JWT_SECRET_TO_USE, if not already set
if [[ -z "${generated_values[ANON_KEY]}" ]]; then
    generated_values["ANON_KEY"]=$(create_jwt "anon" "$JWT_SECRET_TO_USE")
fi

if [[ -z "${generated_values[SERVICE_ROLE_KEY]}" ]]; then
    generated_values["SERVICE_ROLE_KEY"]=$(create_jwt "service_role" "$JWT_SECRET_TO_USE")
fi

# Add any custom variables that weren't found in the template
for var in "FLOWISE_USERNAME" "DASHBOARD_USERNAME" "LETSENCRYPT_EMAIL" "ACME_EMAIL" "REVERSE_PROXY" "TLS_MODE" "WILDCARD_DOMAIN" "LOCAL_CA_CERT" "LOCAL_CA_KEY" "TRAEFIK_ACME_STORAGE" "TRAEFIK_CERT_RESOLVER" "RUN_N8N_IMPORT" "OPENAI_API_KEY" "PROMETHEUS_USERNAME" "SEARXNG_USERNAME" "LANGFUSE_INIT_USER_EMAIL" "N8N_WORKER_COUNT" "WEAVIATE_USERNAME" "NEO4J_AUTH_USERNAME" "COMFYUI_USERNAME" "RAGAPP_USERNAME" "PADDLEOCR_USERNAME" "LT_USERNAME" "LIGHTRAG_USERNAME" "WAHA_DASHBOARD_USERNAME" "WELCOME_USERNAME" "WHATSAPP_SWAGGER_USERNAME" "DOCLING_USERNAME"; do
    if [[ ${found_vars["$var"]} -eq 0 && ${generated_values[$var]+_} ]]; then
        # Before appending, check if it's already in TMP_ENV_FILE to avoid duplicates
        if ! grep -q -E "^${var}=" "$TMP_ENV_FILE"; then
            echo "${var}=\"${generated_values[$var]}\"" >> "$TMP_ENV_FILE" # Ensure quoting
        fi
    fi
done

# --- WAHA API KEY (sha512) --- (moved after .env write to avoid overwrite)

# Second pass: Substitute generated values referenced like ${VAR}
# We'll process the substitutions line by line to avoid escaping issues

# Copy the temporary file to the output
cp "$TMP_ENV_FILE" "$OUTPUT_FILE"

log_info "Applying variable substitutions..."

# Process each generated value
for key in "${!generated_values[@]}"; do
    value="${generated_values[$key]}"
    
    # Create a temporary file for this value to avoid escaping issues
    value_file=$(mktemp)
    echo -n "$value" > "$value_file"
    
    # Create a new temporary file for the output
    new_output=$(mktemp)
    
    # Process each line in the file
    while IFS= read -r line; do
        # Replace ${KEY} format
        if [[ "$line" == *"\${$key}"* ]]; then
            placeholder="\${$key}"
            replacement=$(cat "$value_file")
            line="${line//$placeholder/$replacement}"
        fi
        
        # Replace $KEY format
        if [[ "$line" == *"$"$key* ]]; then
            placeholder="$"$key
            replacement=$(cat "$value_file")
            line="${line//$placeholder/$replacement}"
        fi
        
        # Handle specific cases
        if [[ "$key" == "ANON_KEY" && "$line" == "ANON_KEY="* ]]; then
            line="ANON_KEY=\"$(cat "$value_file")\""
        fi
        
        if [[ "$key" == "SERVICE_ROLE_KEY" && "$line" == "SERVICE_ROLE_KEY="* ]]; then
            line="SERVICE_ROLE_KEY=\"$(cat "$value_file")\""
        fi
        
        if [[ "$key" == "ANON_KEY" && "$line" == "SUPABASE_ANON_KEY="* ]]; then
            line="SUPABASE_ANON_KEY=\"$(cat "$value_file")\""
        fi
        
        if [[ "$key" == "SERVICE_ROLE_KEY" && "$line" == "SUPABASE_SERVICE_ROLE_KEY="* ]]; then
            line="SUPABASE_SERVICE_ROLE_KEY=\"$(cat "$value_file")\""
        fi
        
        if [[ "$key" == "JWT_SECRET" && "$line" == "SUPABASE_JWT_SECRET="* ]]; then
            line="SUPABASE_JWT_SECRET=\"$(cat "$value_file")\""
        fi
        
        if [[ "$key" == "POSTGRES_PASSWORD" && "$line" == "SUPABASE_POSTGRES_PASSWORD="* ]]; then
            line="SUPABASE_POSTGRES_PASSWORD=\"$(cat "$value_file")\""
        fi
        
        # Write the processed line to the new file
        echo "$line" >> "$new_output"
    done < "$OUTPUT_FILE"
    
    # Replace the output file with the new version
    mv "$new_output" "$OUTPUT_FILE"
    
    # Clean up
    rm -f "$value_file"
done

# --- WAHA API KEY (sha512) --- ensure after .env write/substitutions ---
# Generate plaintext API key if missing, then compute sha512:HEX and store in WAHA_API_KEY
if [[ -z "${generated_values[WAHA_API_KEY_PLAIN]}" ]]; then
    generated_values[WAHA_API_KEY_PLAIN]="$(gen_base64 48 | tr -d '\n' | tr '/+' 'AZ')"
fi

PLAINTEXT_KEY="${generated_values[WAHA_API_KEY_PLAIN]}"
if [[ -n "$PLAINTEXT_KEY" ]]; then
    SHA_HEX="$(printf "%s" "$PLAINTEXT_KEY" | openssl dgst -sha512 | awk '{print $2}')"
    if [[ -n "$SHA_HEX" ]]; then
        generated_values[WAHA_API_KEY]="sha512:${SHA_HEX}"
    fi
fi

_update_or_add_env_var "WAHA_API_KEY_PLAIN" "${generated_values[WAHA_API_KEY_PLAIN]}"
_update_or_add_env_var "WAHA_API_KEY" "${generated_values[WAHA_API_KEY]}"

# Hash passwords using bcrypt helper (consolidated loop)
SERVICES_NEEDING_HASH=("PROMETHEUS" "SEARXNG" "COMFYUI" "PADDLEOCR" "RAGAPP" "LT" "DOCLING" "WELCOME")

for service in "${SERVICES_NEEDING_HASH[@]}"; do
    password_var="${service}_PASSWORD"
    hash_var="${service}_PASSWORD_HASH"

    plain_pass="${generated_values[$password_var]}"
    existing_hash="${generated_values[$hash_var]}"

    # If no hash exists but we have a plain password, generate new hash
    if [[ -z "$existing_hash" && -n "$plain_pass" ]]; then
        new_hash=$(generate_bcrypt_hash "$plain_pass")
        if [[ -n "$new_hash" ]]; then
            existing_hash="$new_hash"
            generated_values["$hash_var"]="$new_hash"
        fi
    fi

    _update_or_add_env_var "$hash_var" "$existing_hash"
done

REVERSE_PROXY="${generated_values[REVERSE_PROXY]:-caddy}"
TLS_MODE="${generated_values[TLS_MODE]:-public}"
TRAEFIK_ACME_STORAGE="${generated_values[TRAEFIK_ACME_STORAGE]}"
LOCAL_CA_CERT="${generated_values[LOCAL_CA_CERT]}"
LOCAL_CA_KEY="${generated_values[LOCAL_CA_KEY]}"

generate_proxy_configs "$REVERSE_PROXY"

log_success ".env file generated successfully in the project root ($OUTPUT_FILE)."

# Cleanup any .bak files
cleanup_bak_files "$PROJECT_ROOT"

exit 0
