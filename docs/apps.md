# Apps

An app is a compose file plus routes and secrets, all managed in the interface. Images come from a registry;
Pocketcloud does not build.

## Creating one

*Apps → New app*: a name (`a-z0-9-`, also the compose project name) and the compose file. For a single image the
file is three lines:

```yaml
services:
  web:
    image: ghcr.io/you/site:latest
```

Then add a route (host, service, container port, public or internal), add secrets, and press *Deploy*.

## What Pocketcloud changes in the file

- `ports` are removed. Nothing is reachable except through Caddy and the routes.
- Every service gets `restart: unless-stopped` and `no-new-privileges`.
- The app's secrets are attached as an `env_file` to every service and are available as `${NAME}` for
  interpolation in the file itself (`POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}`).
- The `default` network becomes a bridge named `pc-<app>` with the subnet `172.30.<n>.0/24`; services get static
  addresses in sorted order starting at `.10`. Routes point Caddy at those addresses.

Refused: `build`, `privileged`, `cap_add`, `devices`, host networking or PID namespace, `sysctls`, extra networks,
top-level `secrets`, and bind mounts of host paths. Files the app needs go into
`/var/lib/pocketcloud/apps/<app>/files/` on the server and are referenced as `./files/...`.

## Deploys

*Deploy* pulls the images and runs `docker compose up --wait`. Services with a `healthcheck` must become healthy
within three minutes, the others must be running. If that fails, the previous successful release (its rendered file
and image digests are stored) is started again and the app shows `rolled_back` with the reason. The job page shows
the compose output live; secret values are redacted from it and from container logs.

*Start* brings an app up again without pulling. *Stop* removes the containers and the network, volumes stay.
*Remove* at the bottom of the app's *Settings* tab asks for the name and whether to delete volumes.

## Secrets and environment

Secrets live on the app's *Secrets* tab, sealed with the master key and never shown again; saving a name again sets a new value. Each secret
reaches only the ticked services (all by default): a mail password for the mailer need not be in the website's
environment. Saving with an empty value changes just the services. *Import .env* sets several at once from
`KEY=value` lines. The list groups secrets by the part of the name before the first underscore (`SMTP_HOST` and
`SMTP_PASSWORD` under SMTP) and filters by name or service. A `${NAME}` placeholder
in the compose file is filled from the secret of that name, and the page warns about placeholders without one.
Each service has its own page on the *Services* tab: its state, its plain `environment` entries, the secrets that
reach it and its routes. *Edit* there takes the plain entries as `KEY=value` lines and rewrites the compose file
through the YAML model, so comments in it are lost; use *Edit* on the *Settings* tab for anything beyond values.
The *Logs* tab shows the container logs of one service at a time.

## Internet access

Each app's containers can reach the internet fully (default), not at all, or only on listed TCP ports (for
example 587 for mail). The switch is under *Internet access* on the app's *Network* tab and takes effect at once. DNS keeps working either way,
because Docker's resolver answers from the host. Other apps are never reachable, whatever the setting.

## Hardening hints

The *Hardening suggestions* panel on the app's *Overview* tab (and per service on its page) lists what a service could do better: a pinned image tag, `user`, `read_only`, `cap_drop: [ALL]`,
a healthcheck. They are hints, not rules.

## Vulnerability scans and pinned images

Scans run apart from deploys, so a deploy is not held up by them. Nightly at 05:00 server time Trivy checks the
images every running app uses, by digest, exactly as they run (high and critical, from the local daemon), and
records the result with the app's latest deployment: counts on the *Deployments* tab, the critical findings in the
job log. An app with critical findings, or one whose scan could not run, opens a warning. *Scan* on the app page
scans that app now; *Scan all apps now* under Server → Security scans every running app. *Apply* and a restart
after a reboot recreate the containers
with the images pinned to the digests of the last deployment, so a tag that was moved in the registry cannot
slip in; only *Deploy* resolves tags again.

## Routes

The route form prefills the container port from `ports` or `expose` in the compose file and suggests a host for
the first service without a route. `ports` are stripped at deploy time, so keeping them, or an `expose: [3000]`
line, costs nothing and documents the port.

Hosts are a configured domain itself (`example.com`) or one label below it (`shop.example.com`), because that is
what the certificate covers. For a `www.` alias add a second route to the same service. Any other name below a
configured domain, and so without a route, redirects to the domain itself (`https://example.com/`, temporary
redirect). Public routes take precedence over that fallback. `public`
routes are served on the public address behind the WAF (see security.md), which can be switched off per route; `internal` routes only on the WireGuard address and only resolve through
the VPN. Caddy terminates TLS and forwards plain HTTP with `X-Forwarded-Proto: https`.

## Databases

Run them inside the app's compose file with a named volume, as in the example on the *New app* page. There is no
managed database. With backups enabled, the nightly backup includes the app's volumes and a dump of every running
postgres, mysql or mariadb service (see operations.md, Backups).

## Private registries

*Settings → Registries*: host, username and token, stored encrypted. Every pull of every app uses them. For GitHub Container
Registry use a classic personal access token with `read:packages`.
