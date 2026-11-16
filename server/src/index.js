import { fileURLToPath } from 'node:url';
import path from 'node:path';
import https from 'node:https';
import fs from 'node:fs';
import { installNetguard } from './netguard.js';
import { createApp, startHttpServer } from './app.js';
import { allPassed, runChecks } from './doctor.js';
import { assertBindAllowed, bindHost, labProxyHosts, resolvePort } from './safety.js';
import { hostedFrom, baseUrlFrom } from './config.js';
import { loadAgentKey } from './agentKey.js';
import { chatConfigFrom, createChatClient } from './chatAgent.js';

installNetguard(); // before anything else can open a socket

try { process.loadEnvFile(fileURLToPath(new URL('../../.env', import.meta.url))); } catch { /* no .env */ }

const checks = await runChecks();
if (!allPassed(checks)) {
  for (const c of checks.filter((x) => x.level === 'fail')) console.error(`[poppy-verification] refusing to start: ${c.id}: ${c.detail}`);
  process.exit(1);
}
const host = assertBindAllowed(bindHost(), process.env);
const dataDir = process.env.PVL_DATA_DIR || path.resolve(fileURLToPath(new URL('../../.data', import.meta.url)));
const hosted = hostedFrom(process.env);
console.log(`[poppy-verification] starting in ${hosted ? 'Mock (an in-process reference Company and issuer; reaches nothing)' : 'Real (reaches only the Company and issuer you type)'}; switch at runtime with the Mock / Real toggle`);
const port = resolvePort();
// LAB_ALLOWED_HOSTS (the family lab-proxy's name for this lab) is parsed before the server starts.
const proxyHosts = labProxyHosts(process.env, port);
// The chat tab's live agent needs a model key; without one (or in the hosted build) the chat is the guided script.
const chatCfg = chatConfigFrom(process.env);
const chat = !hosted && chatCfg.apiKey ? { client: createChatClient(chatCfg), model: chatCfg.model } : null;
console.log(`[poppy-verification] chat agent: ${chat ? `live (${chat.model})` : 'guided script (set ANTHROPIC_API_KEY for a live agent)'}`);
// The agent key exists whenever Real is configured, even if the app starts in Mock, so the toggle can switch without a restart.
const app = createApp({ agent: baseUrlFrom() ? loadAgentKey(dataDir) : null, hosted, baseUrl: baseUrlFrom(), proxyHosts, chat, localOrigin: `http://127.0.0.1:${port}` });
if (process.env.PVL_TLS_CERT && process.env.PVL_TLS_KEY) {
  // PingFederate fetches the agent's client metadata over https, so the agent URL needs a certificate PF trusts.
  const server = https.createServer({ cert: fs.readFileSync(process.env.PVL_TLS_CERT), key: fs.readFileSync(process.env.PVL_TLS_KEY) }, app);
  server.listen(port, host, () => console.log(`[poppy-verification] https://${host}:${port}/ (agent client_id ${baseUrlFrom() || 'not set'}/client.json)`));
} else {
  const { url } = await startHttpServer({ port, host, app });
  console.log(`[poppy-verification] ${url} (${host === '127.0.0.1' || host === '::1' || host === 'localhost' ? 'loopback' : `bound to ${host}; in a container compose publishes it on 127.0.0.1 only`})`);
}
console.log(`[poppy-verification] health: /api/health`);
