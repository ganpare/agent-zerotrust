# deploy/warpgate

Warpgate — the SSH bastion (access plane, SR1). Sessions are recorded and
replayable; the agent reaches the host **only** through it.

## Deploy

```bash
docker compose run --rm warpgate unattended-setup   # generates /data/warpgate.yaml
docker compose up -d
```

Interactive alternative: `docker compose run --rm warpgate setup`.
Verify `unattended-setup` flags with `docker compose run --rm warpgate
unattended-setup --help` for the installed version.

## Configure (admin UI at `https://<tailscale-ip>:8888/@warpgate/admin`,
or the generated `/data/warpgate.yaml`)

- SSH listener: bind the **Tailscale IP only** (e.g. `<PROTECTED_HOST_IP>:2222`)
- Role: `ai-muse`
- User: `muse` — public-key credential, no password
- SSH target: `<PROTECTED_HOST>-local` → `127.0.0.1:22`, mapped to the
  unprivileged `ai-muse` user, allowed for role `ai-muse` only
- Session recording: **enabled** — recordings live under `/data`

Config schema reference: `config-schema.json` in the
[warp-tech/warpgate](https://github.com/warp-tech/warpgate) repo.

## Verify

- From an allowed device: `ssh -p 2222 muse@<PROTECTED_HOST_IP>` lands as
  `ai-muse` on the host (use `ssh -F none` if the client's system config
  is broken)
- The session appears in the admin UI and is replayable
- Recording files under `/data` are owned by root — the agent user
  cannot read or delete them (SR3)

See the phase runbook: [deploy/README.md](../README.md).
