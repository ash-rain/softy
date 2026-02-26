#!/usr/bin/env bash
set -euo pipefail

# ── Softy Installer ──────────────────────────────────────────────────────────
# curl -fsSL https://raw.githubusercontent.com/ash-rain/softy/main/install.sh | bash
# ─────────────────────────────────────────────────────────────────────────────

REPO="https://github.com/ash-rain/softy.git"
INSTALL_DIR="${SOFTY_DIR:-$HOME/softy}"
BRANCH="${SOFTY_BRANCH:-main}"

# ── Helpers ──────────────────────────────────────────────────────────────────

info()  { printf '\033[1;34m[softy]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[softy]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[softy]\033[0m %s\n' "$*"; }
fail()  { printf '\033[1;31m[softy]\033[0m %s\n' "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || fail "Required: '$1' is not installed. $2"
}

version_ge() {
  # returns 0 if $1 >= $2 (semver major.minor)
  local IFS=.
  local i a=($1) b=($2)
  for ((i=0; i<${#b[@]}; i++)); do
    [[ ${a[i]:-0} -lt ${b[i]:-0} ]] && return 1
    [[ ${a[i]:-0} -gt ${b[i]:-0} ]] && return 0
  done
  return 0
}

# ── Platform ─────────────────────────────────────────────────────────────────

OS="$(uname -s)"
ARCH="$(uname -m)"
info "Detected $OS $ARCH"

case "$OS" in
  Darwin|Linux) ;;
  *) fail "Unsupported OS: $OS (macOS and Linux only)" ;;
esac

# ── Prerequisites ────────────────────────────────────────────────────────────

info "Checking prerequisites..."

need git   "Install: https://git-scm.com"
need node  "Install Node.js >= 18: https://nodejs.org"
need npm   "Comes with Node.js"
need docker "Install Docker Desktop: https://docker.com/get-started"

NODE_VER="$(node -v | sed 's/^v//')"
if ! version_ge "$NODE_VER" "18.0"; then
  fail "Node.js >= 18 required (found $NODE_VER)"
fi
ok "Node.js $NODE_VER"

if ! docker info >/dev/null 2>&1; then
  fail "Docker daemon is not running. Start Docker Desktop and try again."
fi
ok "Docker is running"

# ── Clone / Update ───────────────────────────────────────────────────────────

if [ -d "$INSTALL_DIR/.git" ]; then
  info "Existing install found at $INSTALL_DIR — pulling latest..."
  git -C "$INSTALL_DIR" fetch origin
  git -C "$INSTALL_DIR" reset --hard "origin/$BRANCH"
else
  info "Cloning softy into $INSTALL_DIR..."
  git clone --depth 1 --branch "$BRANCH" "$REPO" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# ── Node dependencies ───────────────────────────────────────────────────────

info "Installing Node dependencies..."
npm ci --prefer-offline 2>/dev/null || npm install

# ── Work directories ────────────────────────────────────────────────────────

mkdir -p "$HOME/.softy/work" "$HOME/.softy/ghidra-projects"
ok "Created ~/.softy/work and ~/.softy/ghidra-projects"

# ── Docker backend ───────────────────────────────────────────────────────────

info "Building Docker backend (this may take a few minutes on first run)..."
docker compose -f docker/docker-compose.yml build

info "Starting backend container..."
docker compose -f docker/docker-compose.yml up -d

# Wait for health
info "Waiting for backend to become healthy..."
TRIES=0
MAX_TRIES=30
until curl -sf http://localhost:7800/health >/dev/null 2>&1; do
  TRIES=$((TRIES + 1))
  if [ "$TRIES" -ge "$MAX_TRIES" ]; then
    warn "Backend not healthy after ${MAX_TRIES}s. Check: docker logs softy-tools"
    break
  fi
  sleep 1
done

if [ "$TRIES" -lt "$MAX_TRIES" ]; then
  ok "Backend is healthy on port 7800"
fi

# ── Build Electron app ──────────────────────────────────────────────────────

info "Building Electron app..."
npx electron-vite build

# ── Done ────────────────────────────────────────────────────────────────────

echo ""
ok "Softy installed successfully!"
echo ""
info "  Location:  $INSTALL_DIR"
info "  Backend:   http://localhost:7800/health"
echo ""
info "Quick start:"
info "  cd $INSTALL_DIR"
info "  npm run dev          # dev mode with hot-reload"
info "  npm run build        # production build"
echo ""
info "Docker lifecycle:"
info "  npm run docker:up    # start backend"
info "  npm run docker:down  # stop backend"
info "  npm run docker:logs  # view logs"
echo ""
