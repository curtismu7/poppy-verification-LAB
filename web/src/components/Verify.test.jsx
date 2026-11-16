import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import VerifyPanel from "./VerifyPanel";
import ConsentScreen from "./ConsentScreen";

const CATALOG = {
  spec: "https://personalagentprotocol.org/docs/1.0/spec",
  checks: [
    { id: "as-protected-resources", group: "Issuer metadata", title: "AS metadata protected_resources lists the Company", spec: "3.2", level: "must" },
    { id: "s-replay", group: "Poppy-Session", title: "The same Session jti twice", spec: "5.3", level: "should" },
    { id: "o-pkce", group: "Sign-in and tokens", title: "A code redeemed without PKCE", spec: "4.2", level: "must" },
  ],
  defects: { no_protected_resources: "Issuer metadata omits protected_resources" },
};
const REPORT = (fail) => ({ mode: "mock", conformant: !fail, defects: fail ? ["no_protected_resources"] : [], summary: { pass: fail ? 2 : 3, fail: fail ? 1 : 0, warn: 0, skip: 0, total: 3 }, results: [
  { id: "as-protected-resources", status: fail ? "fail" : "pass", detail: fail ? "protected_resources null must include https://company.example" : "ok" },
  { id: "s-replay", status: "pass", detail: "second use refused" },
  { id: "o-pkce", status: "pass", detail: "refused" }] });

let posted;
function mockFetch({ report = REPORT(false), consent } = {}) {
  posted = [];
  vi.stubGlobal("fetch", vi.fn(async (url, init = {}) => {
    const body = init.body ? JSON.parse(init.body) : undefined;
    if (init.method === "POST") posted.push([url, body]);
    const ok = (j, status = 200) => ({ ok: status < 400, status, json: async () => j });
    if (url === "/api/verify/checks") return ok(CATALOG);
    if (url === "/api/verify/run") return ok(report);
    if (String(url).startsWith("/api/mock/consent") && init.method === "POST") return ok({ redirect: "http://127.0.0.1:7820/cb?code=c&state=s&iss=i" });
    if (String(url).startsWith("/api/mock/consent")) return consent ? ok(consent) : ok({ error: "unknown_consent" }, 404);
    return ok({});
  }));
}
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe("Verify tab", () => {
  beforeEach(() => mockFetch());
  it("lists every check before a run, as Not run, grouped, with the spec section", async () => {
    render(<VerifyPanel info={{ source: "mock" }} />);
    expect(await screen.findByTestId("check-as-protected-resources")).toHaveTextContent("Not run");
    expect(screen.getByTestId("check-as-protected-resources")).toHaveTextContent("spec 3.2");
    expect(screen.getByTestId("check-s-replay")).toHaveTextContent("(recommended)");
    expect(screen.getByRole("link", { name: "1.0 specification" })).toHaveAttribute("href", CATALOG.spec);
  });
  it("Mock: runs clean and says no check failed", async () => {
    render(<VerifyPanel info={{ source: "mock" }} />);
    await screen.findByTestId("check-o-pkce");
    fireEvent.click(screen.getByTestId("verify-run"));
    expect(await screen.findByTestId("verify-summary")).toHaveTextContent("No check failed. 3 passed");
    expect(posted[0]).toEqual(["/api/verify/run", { defects: [] }]);
    expect(screen.getByTestId("check-as-protected-resources")).toHaveAttribute("data-status", "pass");
  });
  it("Mock: a defect that is switched on is sent, and the check that names it shows Fail with its reason", async () => {
    mockFetch({ report: REPORT(true) });
    render(<VerifyPanel info={{ source: "mock" }} />);
    await screen.findByTestId("check-o-pkce");
    fireEvent.click(screen.getByText(/Defects to switch on/));
    fireEvent.click(screen.getByTestId("defect-no_protected_resources"));
    fireEvent.click(screen.getByTestId("verify-run"));
    expect(await screen.findByTestId("verify-summary")).toHaveTextContent("1 check failed");
    expect(posted[0][1]).toEqual({ defects: ["no_protected_resources"] });
    const row = screen.getByTestId("check-as-protected-resources");
    expect(row).toHaveAttribute("data-status", "fail");
    expect(row).toHaveTextContent("must include https://company.example");
    fireEvent.click(screen.getByRole("button", { name: "Fail" }));
    expect(screen.queryByTestId("check-s-replay")).toBeNull();
  });
  it("Real: needs a Company and an issuer, then sends them with the probe path", async () => {
    render(<VerifyPanel info={{ source: "real", defaults: {} }} />);
    await screen.findByTestId("check-o-pkce");
    expect(screen.getByTestId("verify-run")).toBeDisabled();
    fireEvent.change(screen.getByTestId("verify-origin"), { target: { value: "https://company.example" } });
    fireEvent.change(screen.getByTestId("verify-issuer"), { target: { value: "https://auth.company.example" } });
    expect(screen.getByTestId("verify-run")).toBeEnabled();
    fireEvent.click(screen.getByTestId("verify-run"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0][1]).toEqual({ origin: "https://company.example", issuer: "https://auth.company.example", probePath: "/poppy/api/v1/me" });
  });
});

describe("Mock consent screen", () => {
  const CONSENT = { id: "c1", clientName: "Verification agent", clientId: "https://agent.example/client.json", company: "company.example", scopes: [{ name: "orders:read", description: "See your orders", changes: "none", personal_data: true }, { name: "account:close", description: "Close your account", changes: "irreversible", personal_data: true }] };
  it("names the Company, the agent and each scope with what it can change, and says it is a mock issuer", async () => {
    mockFetch({ consent: CONSENT });
    render(<ConsentScreen id="c1" />);
    expect(await screen.findByTestId("consent")).toHaveTextContent("company.example wants to let an agent act for you");
    expect(screen.getByTestId("consent")).toHaveTextContent("MOCK ISSUER");
    expect(screen.getByTestId("consent")).toHaveTextContent("cannot be undone");
    expect(screen.getByTestId("consent")).toHaveTextContent("reads only");
  });
  it("sends only the ticked scopes on Allow, and nothing is granted when all are unticked", async () => {
    mockFetch({ consent: CONSENT });
    render(<ConsentScreen id="c1" />);
    await screen.findByTestId("consent");
    fireEvent.click(screen.getByTestId("grant-account:close"));
    fireEvent.click(screen.getByTestId("consent-approve"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0][1]).toEqual({ id: "c1", action: "approve", scopes: ["orders:read"] });
    fireEvent.click(screen.getByTestId("grant-orders:read"));
    expect(screen.getByTestId("consent-approve")).toBeDisabled();
  });
  it("Decline sends deny; an unknown id says so instead of showing a form", async () => {
    mockFetch({ consent: CONSENT });
    render(<ConsentScreen id="c1" />);
    await screen.findByTestId("consent");
    fireEvent.click(screen.getByTestId("consent-deny"));
    await waitFor(() => expect(posted[0][1]).toEqual({ id: "c1", action: "deny", scopes: undefined }));
    cleanup();
    mockFetch({});
    render(<ConsentScreen id="gone" />);
    expect(await screen.findByTestId("consent-gone")).toBeInTheDocument();
  });
});
