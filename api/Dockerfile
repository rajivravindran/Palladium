# River3 API image: the FastAPI hub plus the built operator console it serves.
#
# Build context is the REPOSITORY ROOT (the console lives in ui/, the API in api/):
#   docker build -f api/Dockerfile .            # or: docker compose -f deploy/docker-compose.yml build
# COPY paths below are therefore relative to the repo root, and api/Dockerfile.dockerignore
# (BuildKit's per-Dockerfile ignore file) keeps venvs, tests, node_modules and the other
# components out of the context.
#
# TODO(pilot): pin both base images by digest, not just tag. Tags move; a digest does not.
#   docker pull node:22-bookworm-slim && docker inspect --format '{{index .RepoDigests 0}}' node:22-bookworm-slim
#   docker pull python:3.12-slim      && docker inspect --format '{{index .RepoDigests 0}}' python:3.12-slim
# then write  FROM node:22-bookworm-slim@sha256:...  /  FROM python:3.12-slim@sha256:...

# ---------------------------------------------------------------- stage 1: console
# Node only exists to run tsc + vite; nothing from this stage ships except /out.
FROM node:22-bookworm-slim AS console

# NODE_ENV is deliberately NOT set to production here: npm would then skip devDependencies,
# and vite, typescript and the React plugin are devDependencies. vite build minifies regardless.
ENV npm_config_update_notifier=false

WORKDIR /ui

# Lockfile first so the dependency layer is cached across source-only changes.
# `npm ci` installs exactly package-lock.json and fails if it disagrees with package.json.
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY ui/index.html ui/tsconfig.json ui/vite.config.ts ./
COPY ui/src ./src

# vite.config.ts points outDir at ../api/static for local development (FastAPI serves it from
# there). In the image the API lands in /app, so the CLI overrides outDir; --emptyOutDir is
# required because the target is outside the vite root. Type-check first, exactly as `npm run build` does.
RUN npx tsc --noEmit && npx vite build --outDir /out --emptyOutDir

# ---------------------------------------------------------------- stage 2: api
FROM python:3.12-slim AS api

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first (cached layer), from the exact lock file
COPY api/requirements.lock .
RUN pip install --require-virtualenv=false -r requirements.lock

COPY api/river3_api ./river3_api
COPY api/migrations ./migrations
COPY api/alembic.ini .

# main.py resolves STATIC_DIR as <package parent>/static, i.e. /app/static for /app/river3_api.
# It serves /app/static/index.html for the SPA and mounts /app/static/assets at /assets.
COPY --from=console /out ./static

# Unprivileged user; no shell login, no home directory writes needed. Everything above is
# root-owned and world-readable, which is all a read-only root filesystem needs.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin river3
USER 10001

ENV RIVER3_ENV=production
EXPOSE 8000

# Liveness only (no DB): the compose file adds a readiness probe against /api/ready.
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=2).status==200 else 1)"

# One worker per container: the live stream, ticket replay cache, canary replay cache and auth
# throttle are in-process. Scale by running more containers behind a proxy only after moving
# those to a shared store (see docs/ARCHITECTURE.md, "Scaling").
CMD ["uvicorn", "river3_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", \
     "--no-server-header", "--no-access-log", "--timeout-graceful-shutdown", "10"]
