# Agents

An agent is a program that manages apps for you, Claude Code on your laptop for one. It talks to the daemon over
MCP (the Model Context Protocol) at `https://pocketcloud.<domain>/mcp`, a path on the interface host, which only
exists on the WireGuard listener: with the tunnel up the endpoint is there, without it nothing answers. There is
nothing to install on the server and no client on your machine; the daemon is the MCP server.

## Tokens

*Settings → Agents* creates a token per agent, with a name and a scope:

- **read**: apps, compose files, routes, secret names, container logs, jobs, server status, alerts and events.
- **deploy**: also create an app, replace its compose file, set and remove secrets and routes, change internet
  access, deploy, apply, start and stop.

Neither scope removes an app, restores, changes backups, upgrades or reboots the server, or touches VPN devices,
ssh keys, registries, notifications or the account; those stay in the interface. The token is shown once, with
the command to paste; the database keeps only its hash. *Revoke* refuses the next request. Everything an agent
changes is in *Alerts → Audit log* as `agent:<name>`, and a request with a missing or unknown token is audited
as `agent.auth_failed` and answered after a delay.

## Claude Code

With the tunnel active, once:

```sh
claude mcp add --transport http pocketcloud https://pocketcloud.<domain>/mcp --header "Authorization: Bearer pc_…" --scope user
```

`--scope user` makes the server available in every project on this machine; leave it out for the current project
only. For a project's `.mcp.json`, with the token in an environment variable instead of the file:

```json
{
  "mcpServers": {
    "pocketcloud": {
      "type": "http",
      "url": "https://pocketcloud.<domain>/mcp",
      "headers": { "Authorization": "Bearer ${POCKETCLOUD_TOKEN}" }
    }
  }
}
```

`/mcp` inside Claude Code shows the server and its tools. Then ask: *which apps run and are any unhealthy?*,
*show the last 100 log lines of the web service of shop*, *deploy shop and tell me when it is up*. The server's
instructions tell the agent to show you what will change and ask before a deploy, stop or removal of a route or
secret, and to follow a deploy job until it is done, failed or rolled back.

Claude Code waits five minutes for an idle HTTP tool call by default; a deploy is followed with the `job` tool in
slices of 45 seconds, so nothing needs changing. `MCP_TOOL_TIMEOUT` and `CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT` are
the knobs if you have a reason.

## Tools

| tool | scope | what |
|---|---|---|
| `list_apps` | read | every app: status, routes, last deployment, active job |
| `get_app` | read | one app: compose file, routes, secret names and the services they reach, placeholders without a secret, hardening hints, containers, deployments, recent jobs |
| `logs` | read | the last lines (10 to 5000) of one service's container, secret values redacted |
| `list_jobs`, `job` | read | jobs and their logs; `job` can wait up to 45 s for a running one |
| `server_status` | read | version, uptime, docker, pending updates and reboot, certificates, backups, host load, open alerts |
| `alerts`, `events` | read | what the Alerts page shows |
| `create_app`, `update_compose` | deploy | validated like the interface; a changed file takes effect with the next deploy |
| `set_secret`, `generate_secret`, `delete_secret` | deploy | `generate_secret` makes a random value on the server that never passes through the chat |
| `add_route`, `delete_route`, `set_egress` | deploy | applied at once, as in the interface |
| `deploy`, `apply`, `start_app`, `stop_app` | deploy | start the job and return its id; follow it with `job` |

Secrets and the chat: a value passed to `set_secret` is part of the conversation, wherever that is stored.
Prefer `generate_secret` for passwords that only containers need to know, and type values you hold (an API key)
into the app's *Secrets* tab yourself; the agent is told the same.

## Other clients

Any MCP client that speaks Streamable HTTP with a bearer header works the same way: `POST /mcp` with
`Authorization: Bearer pc_…`. Both protocol revisions are served (`2025-11-25` with its `initialize` handshake and
`2026-07-28` without), statelessly, so a daemon restart or upgrade never strands a session.
