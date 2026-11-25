<!--
  Story wording for poppy-verification-LAB. The lab serves this file at GET /api/story (the shared Story parser);
  the live Story reads that. No recorded video exists yet; when one is made it must read this same file.

  Rules for editing safely:
  - The first page has a "## Header" naming what the demo shows (rule 29): keep it on the Opening Slide and on mock_note.
  - Don't rename a "# Opening Slide" / "# Closing Slide" / "# Slide: <key>" / "# Step: <key>" heading, and don't rename
    a "## Header" / "## Title" / "## Text" / "## Lead" / "## Verdict" / "## Column A: ..." / "## Column B: ..." heading.
  - A column heading's label IS shown on the slide; edit it freely, keep "Column A:" / "Column B:" at the line's start.
  - Keep each bullet on its own line starting with "- ".
  - Keep slide text to about 40 words.
  - Say only what the run proved. Mock wording (sample_*) says simulated; it never claims a live result.
  - Public-safe: no internal hostnames, tenant or client ids, keys, customer names. Only .example hosts.
  - "---" on its own line separates sections. Keep those.
-->

# Opening Slide

## Header
Poppy, verified against the spec

## Title
The Personal Agent Protocol, checked line by line

## Lead
An agent arrives at a Company with no client registration and no shared secret: it names itself with a URL, the person signs in, and every call carries a signed session. This lab checks each of those claims against the published spec.

## Column A: What you will see
- The Run tab: discover, sign in, call
- The Verify tab: 107 checks against the spec
- A deliberate defect, and the check that catches it

## Column B: What it proves
- Discovery: poppy.json and protected-resource metadata
- Sign-in: PAR, CIMD, PKCE, scoped consent
- The call: a bearer token plus a signed Poppy-Session

## Verdict
A pass means this suite saw the right behaviour. It is not a certification.

---

# Slide: why_poppy

## Title
Why Poppy exists

## Lead
Today a Company faces two choices for an agent at its door: block it, or let it sign in as the person and do anything they can. Poppy is the middle ground both sides agree on.

## Column A: For the Company
- One published document, any agent
- Which scopes an agent may ask for
- Every visit identified and auditable

## Column B: For the person and the agent
- No password ever handed to the agent
- Consent the person grants and can revoke
- One protocol for every Company

## Verdict
Built on the OAuth and HTTPS the Company already runs.

---

# Step: run_intro

## Title
The Run tab: one click through the whole flow

## Text
This page plays the personal agent against the Company. Press "Run it (1 click)": discover poppy.json, push an authorization request (PAR), sign in on the Company's own page, then call the API with the token and a signed Poppy-Session.

---

# Step: run_one_click

## Title
Press "Run it (1 click)"

## Text
One click runs the whole agent flow against the Company: discovery, PAR, sign-in, token, call. Each request lands as a row below with its wire detail — press it, and the story carries on when the run lands.

---

# Step: run_discover

## Title
Discovery comes first

## Text
The agent reads two public documents: poppy.json, which names the scopes and APIs, and the protected-resource metadata, which names the authorization server. The resource must be exactly the origin — a look-alike path is refused.

---

# Step: run_par

## Title
The authorization request is pushed, not passed

## Text
Instead of carrying the request through the browser, the agent sends it ahead of time (PAR) and gets a short request URI. The person's browser carries only that, so nothing can be altered on the way.

---

# Step: run_authorize

## Title
The person signs in on the Company's own page

## Text
There is no client id to register: the client_id is the agent's metadata URL, and the authorization server fetches it (CIMD). The person signs in and grants only the scope the agent asked for — nothing more is issued.

---

# Step: run_token

## Title
The token names the agent, not a machine

## Text
The access token carries the agent's URL as client_id, and only the granted scope. It is what the Company later checks — but on its own it is not enough to make a call.

---

# Step: run_call

## Title
The call: two proofs, every time

## Text
Each API call carries the access token and a Poppy-Session: a short-lived JWT signed by a key the agent's long-lived key vouched for. The session names this method, this URL, this token — a stolen token alone is not enough.

---

# Step: run_done

## Title
Signed in, called, verified

## Text
The response came from the Company's API: the person allowed it, the agent identified itself, and the session proved it. Open the token page below to read every claim.

---

# Step: run_unconfigured

## Title
Sign-in needs this agent to be reachable

## Text
In Real mode the authorization server fetches this agent's metadata, so the lab needs a public HTTPS URL (PVL_AGENT_BASE_URL). Reading the Company works without it; sign-in and the call are skipped honestly.

---

# Step: verify_intro

## Title
The Verify tab: the spec as a checklist

## Text
107 checks, each tied to a section of the published spec: discovery, issuer metadata, Poppy-Session rules, sign-in and tokens, resources. Run the suite against the reference Company — in Mock it passes everything.

---

# Step: verify_run

## Title
Run the suite

## Text
Press Run verification. Every check passes against the reference Company and issuer. That is the baseline; now prove the suite can fail.

---

# Step: verify_all_pass

## Title
No check failed

## Text
The suite ran and no check failed against the clean reference. A verifier that cannot fail proves nothing, so next you switch a defect on.

---

# Step: verify_defect

## Title
Break the Company on purpose

## Text
Tick the defect that leaves protected_resources out of the issuer metadata, then run the suite again. The spec makes that document a MUST (section 3.2): without it the agent cannot safely sign in.

---

# Step: verify_run2

## Title
Run the suite with the defect in

## Text
Press Run verification again. This time the suite runs against the broken Company, and the check that names the missing document fails.

---

# Step: verify_defect_caught

## Title
The named check fails

## Text
The check that names that rule failed with its reason, and the summary counts it. This is the point of the suite: each defect has a check that catches exactly it.

---

# Closing Slide

## Title
What a pass means

## Lead
The suite checked discovery, metadata, the Poppy-Session rules, sign-in and tokens against the published spec — and says which section each check comes from.

## Column A: The lab's promise
- Each defect has a check that catches it
- Mock runs fully offline; nothing leaves this machine
- Real probes only the Company and issuer you name

## Column B: What it is not
- Not a certification
- Not every extension: Device Sign-In, DPoP and the Company Agent channel are not checked
- Not a substitute for reading the spec

## Verdict
Try it against a Company you trust — then one you do not.

---

# Slide: mock_note

## Header
Poppy, verified against the spec

## Title
Simulated run

## Lead
This page is in Mock mode: the reference Company and issuer run inside this app, nothing leaves this machine, and every token is a mock token.

## Column A: What is simulated
- The Company and the issuer are built into this app
- Every token is a mock token, signed by the mock issuer
- The walk says simulated at each step

## Column B: What is real
- The checks the suite runs are the published spec's rules
- The flow's shape is the one a real agent walks
- Switch to Real to point the lab at a Company you name

## Verdict
Nothing leaves this machine.

---

# Step: sample_run_par

## Title
The authorization request is pushed (simulated)

## Text
In this simulated run the agent pushes the authorization request to the mock issuer and carries only the short request URI through the sign-in. The real flow works the same way against a real authorization server.

---

# Step: sample_run_token

## Title
The token names the agent (simulated)

## Text
The mock token carries the agent's metadata URL as client_id and only the granted scope. It is a mock token, signed by the mock issuer — the shape is what matters.

---

# Step: sample_run_call

## Title
The call: two proofs (simulated)

## Text
The simulated call carries the mock token and a signed Poppy-Session naming this method, this URL and this token. The mock Company verified both before answering.

---

# Step: sample_verify_run

## Title
Run the suite (simulated)

## Text
The suite runs against the in-process reference. Nothing leaves this machine.

---

# Step: observability

## Title
What the run left behind

## Text
Every step is recorded with its time: the discovery reads, the PAR, the token, the call, and the suite verdicts. This is the trail an operator would audit.

---

# Step: sample_observability

## Title
What the simulated run left behind

## Text
These records are from the simulated run you just watched: the discovery reads, the PAR, the mock token, the signed call and the suite verdicts, each with its time.
