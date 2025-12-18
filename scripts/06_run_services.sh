#!/bin/bash
# =============================================================================
# 06_run_services.sh - Service launcher
# =============================================================================
# Starts all selected services using Docker Compose via start_services.py.
#
# Pre-flight checks:
#   - Verifies .env, docker-compose.yml, and Caddyfile exist
#   - Ensures Docker daemon is running
#   - Makes start_services.py executable if needed
#
# The actual service orchestration is handled by start_services.py which:
#   - Starts services in correct dependency order
#   - Handles profile-based service selection
#   - Manages health checks and startup timeouts
#
# Usage: bash scripts/06_run_services.sh
# =============================================================================

set -e

# Source the utilities file and initialize paths
source "$(dirname "$0")/utils.sh"
init_paths

cd "$PROJECT_ROOT"

# Check required files
log_subheader "Pre-flight Checks"
require_file "$ENV_FILE" ".env file not found in project root."
require_file "$PROJECT_ROOT/docker-compose.yml" "docker-compose.yml file not found in project root."
require_file "$PROJECT_ROOT/start_services.py" "start_services.py file not found in project root."

# Load environment to determine proxy selection
load_env || true
ensure_proxy_profile
require_proxy_config

# Check if Docker daemon is running
if ! docker info > /dev/null 2>&1; then
  log_error "Docker daemon is not running. Please start Docker and try again."
  exit 1
fi

# Validate proxy configuration before launching
if [[ "${REVERSE_PROXY:-caddy}" == "traefik" ]]; then
  log_info "Validating Traefik configuration..."
  docker run --rm \
    -v "$PROJECT_ROOT/traefik/traefik.yml:/etc/traefik/traefik.yml:ro" \
    -v "$PROJECT_ROOT/traefik/traefik.dynamic.yml:/etc/traefik/traefik.dynamic.yml:ro" \
    traefik:v3.1 traefik check --configfile /etc/traefik/traefik.yml || {
      log_error "Traefik configuration validation failed."
      exit 1
    }
else
  log_info "Validating Caddy configuration..."
  docker run --rm \
    -v "$PROJECT_ROOT/Caddyfile:/etc/caddy/Caddyfile:ro" \
    caddy:2-alpine caddy validate --config /etc/caddy/Caddyfile || {
      log_error "Caddyfile validation failed."
      exit 1
    }
fi

# Ensure start_services.py is executable
if [ ! -x "$PROJECT_ROOT/start_services.py" ]; then
  log_warning "start_services.py is not executable. Making it executable..."
  chmod +x "$PROJECT_ROOT/start_services.py"
fi

log_subheader "Starting Services"
log_info "Launching services using start_services.py..."
# Execute start_services.py
"$PROJECT_ROOT/start_services.py"

exit 0
