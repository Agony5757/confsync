# Upgrading confsync

Rollout guide for existing deployments. Example below upgrades **0.1.x →
0.2.x** (the Gitea login release), but the same steps apply to any version.

What 0.2.0 changes on the server:

- **New (optional) Gitea login**: Web UI OAuth + Gitea access tokens accepted
  by the REST API. With no Gitea env vars set, behavior is identical to 0.1.x.
- **DB schema**: `users` gains a nullable `gitea_id` column + unique index.
  Applied **automatically on first start** (idempotent `ALTER TABLE`, < 1 s,
  no data rewrite). 0.1.x code keeps working against the migrated DB (it
  ignores the extra column), so rollback needs no schema undo.
- **New public endpoint** `GET /api/v1/version`, and a `confsync-server
  backup` command for hot backups.

## 1. Server upgrade (Docker)

The image builds from the local checkout (`deploy/Dockerfile` copies
`server/`), so "upgrading" = update the code on the server + rebuild. State
lives in the `confsync-data` volume (`/data`: `server.db`, `master.key`) and
survives rebuilds untouched.

```bash
# 0) hot backup — no downtime needed (snapshot via sqlite online-backup API)
docker exec confsync-server confsync-server backup --out /data/backups/pre-0.2.0
docker cp confsync-server:/data/backups/pre-0.2.0 .   # keep a copy off-container

# 1) bring the new code (adjust path/remote to your setup)
cd /root
mv confsync confsync.old-0.1.0
git clone --depth 1 -b v0.2.0 https://github.com/Agony5757/confsync.git
cp confsync.old-0.1.0/deploy/.env confsync/deploy/.env   # secrets carry over

# 2) rebuild & restart (schema migration runs on startup)
cd confsync/deploy && docker compose up -d --build

# 3) verify
curl -s https://<your-host>/api/v1/version        # → {"server": "0.2.0"}
docker logs confsync-server --tail 20
confsync pull --app <app> --name <doc>            # from any logged-in client
```

Rollback:

```bash
cd /root/confsync.old-0.1.0/deploy && docker compose up -d --build
```

No schema rollback required. Only if data itself must be restored:
`docker compose down`, copy `server.db` + `master.key` from the backup into
the volume (`/data`), `docker compose up -d`.

### Enabling Gitea login (optional, 0.2.0+)

1. In your Gitea: *Settings → Applications → Manage OAuth2 Applications*,
   redirect URL `https://<confsync-host>/auth/gitea/callback`.
2. Add to `deploy/.env` and `docker compose up -d`:
   `CONFSYNC_GITEA_URL`, `CONFSYNC_GITEA_CLIENT_ID`,
   `CONFSYNC_GITEA_CLIENT_SECRET`.
3. Access tokens (CLI login): create in Gitea with scope `read:user`; the
   same login allowlist applies; server-side verification cache is ~5 min.

### Bare metal (no Docker)

```bash
pip install -U confsync-server==0.2.0     # or: pip install <path-to-repo>/server
confsync-server backup                    # $CONFSYNC_HOME/backups/<timestamp>
confsync-server service restart
```

## 2. Client upgrade

```bash
pip install -U confsync-client            # or: uv tool upgrade confsync-client
confsync --version
```

Embedded in your own apps: pin `confsync-client>=0.2.0` in the app's
dependencies.

- **No re-login needed** — `~/.confsync/credentials.json` and the REST API
  are unchanged across versions.
- Compatibility matrix:

| Client | Server | Works? |
|---|---|---|
| 0.1.x | 0.2.x | yes (REST unchanged) |
| 0.2.x | 0.1.x | yes, except Gitea tokens and `/api/v1/version` |
| Gitea-token login | | needs client ≥ 0.2.0 **and** server ≥ 0.2.0 |

- Check a server's version any time: `curl https://<host>/api/v1/version`.
- More offline docs: `confsync help` / `confsync help upgrade`.

## Checklist (summary)

1. `confsync-server backup` (+ copy backup out of the container)
2. update code on the server, keep `deploy/.env`
3. `docker compose up -d --build`
4. `curl /api/v1/version` → expected version; spot-check a `pull`
5. clients: `pip install -U confsync-client` when you want Gitea tokens
