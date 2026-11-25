# Legacy deployment files

Superseded by the one production deployment in [`deploy/`](../../deploy/README.md) (`deploy/compose.yaml`, run by
`deploy/install.sh`). Kept, unchanged apart from their paths, for installations that still run them; nothing new
should be built on them.

- `docker-compose.production.yml` and `hawk_production_stack.sh`: the production stack layered on
  `infra/docker-compose.demo.yml` (see `docs/deployment/production-single-node-compose.md`).
- `Dockerfile.api.*-hotpatch`, `Dockerfile.hawk-monitoring-loop-break`, `Dockerfile.hmair-h2-browser-overlay` and the
  `docker-compose.*.override.yml` files: one-off images and overrides that copied single source files into an
  already-built demo or production image. `deploy/install.sh` builds the images from the whole source instead.

Paths inside these files are relative to the repository root (the build context) or to `infra/` (the compose project
directory of `infra/docker-compose.demo.yml`), as before, so they work from here unchanged.
