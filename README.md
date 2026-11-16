# Poppy Verification LAB

Tier: Tester

Repo: https://github.com/curtismu7/poppy-verification-LAB

**Fork of [poppy-agent-tester-LAB](https://github.com/curtismu7/poppy-agent-tester-LAB)** (agent side, at its commit `db7f301`). What changed: this fork carries its own Company (relying party) and issuer, a verification suite, and fixes found by reviewing the Relying Party Implementation Guide against the published spec. Details: [docs/guide-review.md](docs/guide-review.md).

Checks a Company and its authorization server against the **Personal Agent Protocol 1.0** (published 2026-11-14, <https://personalagentprotocol.org/docs/1.0/spec>). It is the published protocol spec, not an IETF RFC; the RFCs it builds on (6749, 7636, 7523, 8414, 9126, 9207, 9449, 9728 and others) are dependencies.

- **Verify tab:** 63 checks, each tied to a spec section: discovery, issuer metadata (including the `protected_resources` link the guide left out), `Poppy-Session` (typ, alg, delegation, aud, htu, htm, iat, replay, ath, Poppy-Version, status codes), sign-in (PKCE, `iss` on every response, scopes never exceed the request, CIMD rules, refresh, revocation) and resources (audience, MCP token binding, scope).
- **Mock** (default): a reference Company and issuer run inside this app and pass every check. Switch on any of 28 deliberate **defects** and the check that names it fails, so you can see the suite catch a bad Company. Nothing leaves your machine; every token is a mock token.
- **Real:** reads the Company and the issuer you type and sends `Poppy-Session` probes with this agent's own key. Only those two hosts are contacted. Checks that need a person to sign in are skipped there; use the Run it tab for those.
- **Run it / Agent chat:** play the personal agent step by step (discover, PAR, sign in, signed call). In Mock the issuer's consent screen is part of this app.

A pass means this suite saw the right behaviour. It is not a certification.

## Run from a clone

Prerequisites: Node 26. Docker (OrbStack) only for the Docker form.

```
git clone https://github.com/curtismu7/poppy-verification-LAB.git
cd poppy-verification-LAB
npm ci
npm run build
npm run doctor
npm start
```

## Ports, and what to do if the port is taken

```
Ports: poppy-verification-LAB listens on 7821 (set with PORT, default 7821).
Port range for this app: 7800-7999.

If the port is taken:
1. Find what is using it:
   lsof -iTCP:7821 -sTCP:LISTEN -n -P
2. If it is an old copy of this app, stop that process: kill <PID>.
3. If it is something else, stop it, or start this app on another port:
   PORT=<other port> npm start
```

Other variable: `HOST_PORT=7821` (Docker host port). Keep both inside 7800-7999. The Vite dev server uses 7821 (`VITE_PORT`).

## Run it

```sh
./scripts/run.sh            # http://localhost:7821  (npm ci, build, doctor, start)
npm test                    # server, web and repo tests
npm run doctor              # preflight, same checks as /api/health
```

Docker (OrbStack): `HOST_PORT=7821 docker compose up --build -d`. It starts in Mock. Real needs `PVL_AGENT_BASE_URL` (an https URL an issuer can reach for this agent) and the certificate settings in [docs/setup.md](docs/setup.md); with it set the app starts in Real, and the header toggle switches without a restart.

The **Agent chat** tab is a guided script by default. With `ANTHROPIC_API_KEY` in `.env` (Real only; Mock makes no network call) it becomes a live Claude agent whose three tools are the same real steps. The tools take no host, so nothing the model reads can point the agent elsewhere.

## Presenting

Press `P` for presenter mode; the banner stays. The talk track is in [docs/talk-track.md](docs/talk-track.md).

## Safety

See [docs/safety.md](docs/safety.md). Loopback bind, same-origin writes, Mock opens no socket, Real contacts only the hosts you type, secrets never returned.

## Status and honest limits

- Mock: 107 of 107 checks pass on the clean reference, with PAR required or not. Each of the 28 defects trips exactly the checks pinned in `server/test/verify-suite.test.js`, and 47 further subtle mutants of the reference (`server/test/verify-mutation.test.js`) are all caught. Those mutants came from an independent review that found the first 63-check suite missed 37 of 46.
- Every refusal check has a positive control and names the reason it expects, so a refusal for another reason (for example PAR required) is not a pass. A report with skipped checks says so: `conformant` means no failure, `complete` means every check ran.
- The reference is **not** a certified implementation and does not cover: Device Sign-In, DPoP, browser join (`poppy:browser-sign-in`, `web.unscoped`), the Company Agent conversation channel, the tasks endpoint, the extensions. The suite does not check those either.
- Real mode against PingFederate: proven in the parent lab (2026-11-15) with a metadata layer in front, because PingFederate publishes no `protected_resources`. This fork's agent **refuses to sign in** without it (spec 3.2), so a bare PingFederate fails discovery on purpose.
- Not run against a real tenant by this fork.
- `prompt=consent` (spec 4.2) is sent only when the issuer's metadata lists it in `prompt_values_supported`; whether PingFederate shows consent without it is UNVERIFIED (discovery shows a warning).
- Real mode contacts exactly the Company and issuer you type (host and port), including loopback or private addresses, because a local run against your own PingFederate needs that. It is a loopback-only app with a Host check; do not expose it.
- The Mock/Real mode is per workspace (the browser's `X-Workspace`), so one visitor switching does not change another's.
- Spec sections 10.7, 10.8 and 11 were summarised, not read verbatim, when the checks were written; the Operations extension was not read.
