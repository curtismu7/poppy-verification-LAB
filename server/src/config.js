// Deployment configuration (rule 19). One image, two modes that switch at runtime: Mock (an in-process reference Company and issuer,
// fully offline) and Real (the Company and issuer you type, with this agent's real identity).
// Default: Real when the agent URL is configured, else Mock. MODE=real or MODE=mock chooses. FAIL CLOSED: any other MODE value
// (MODE=MOCK, MODE=hosted, a typo) is Mock, never Real, so a typo cannot start a build that reaches the network by accident.
export const modeFrom = (env = process.env) => {
  const m = env.MODE;
  if (m === undefined || m === '') return String(env.PVL_AGENT_BASE_URL || '').trim() ? 'real' : 'mock';
  return m === 'real' ? 'real' : 'mock';
};
export const hostedFrom = (env = process.env) => modeFrom(env) === 'mock';
export const baseUrlFrom = (env = process.env) => String(env.PVL_AGENT_BASE_URL || '').replace(/\/+$/, '');

// Suggested defaults for the Run it form (owner rule 2026-11-14: a visitor can one-click run it).
// Each deployment names its own Company origin and PingFederate issuer via env; empty by default
// (the placeholders stay .example, per the no-identifiers rule) so nothing ships a real host.
export const demoDefaultsFrom = (env = process.env) => ({
  origin: String(env.PVL_DEMO_COMPANY_ORIGIN || '').trim(),
  issuer: String(env.PVL_DEMO_PF_ISSUER || '').trim(),
  // The second authorization server the page can preselect (PingOne). Empty = the option is shown as not configured here.
  p1Issuer: String(env.PVL_DEMO_P1_ISSUER || '').trim(),
  scope: String(env.PVL_DEMO_SCOPE || '').trim(),
});

// Optional login_hint sent with every sign-in (PVL_DEMO_LOGIN_HINT), so the authorization server pre-fills the username.
// Kept out of demoDefaultsFrom so it is not published in /api/state.
export const loginHintFrom = (env = process.env) => String(env.PVL_DEMO_LOGIN_HINT || '').trim();
