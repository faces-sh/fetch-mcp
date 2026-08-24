// The uniform failure envelope: shape, evidence, redaction, and the paths that used to swallow.
//
// Every assertion is written against Maestro's docs/MCP_FAILURE_ENVELOPE.md: isError is always set,
// the code always leads, an HTTP failure always carries the literal status line AND the site's body
// byte for byte, a transport failure never invents one, and no credential survives the round trip.

import { describe, it, expect, beforeEach, afterAll, jest } from "bun:test";
import dns from "node:dns";
import http from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Fetcher } from "./Fetcher";
import { wrapResult } from "./circuitBuffer";
import {
  BODY_LIMIT,
  TRUNCATION_SUFFIX,
  formatEnvelope,
  redact,
  statusLine,
  transportFailure,
} from "./envelope";

const originalFetch = globalThis.fetch;
const originalLookup = dns.promises.lookup;
const mockFetch = jest.fn();

afterAll(() => {
  globalThis.fetch = originalFetch;
  dns.promises.lookup = originalLookup;
});

/** A response shaped like the real thing, with a readable body stream. */
function response(status: number, body: string, statusText?: string): any {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText,
    url: "https://example.com",
    headers: { get: () => null },
    body: new Blob([body]).stream(),
    text: async () => body,
  };
}

/** The failure shape Node's fetch really produces: a flat message over a coded cause. */
function nodeFetchFailure(code: string, message = "fetch failed"): Error {
  const err = new TypeError(message);
  (err as { cause?: unknown }).cause = Object.assign(new Error(code), { code });
  return err;
}

describe("redaction (rule 8)", () => {
  it("strips userinfo out of an echoed URL", () => {
    expect(redact("could not reach https://alex:hunter2@example.com/x")).toBe(
      "could not reach https://<redacted>@example.com/x",
    );
  });

  it("strips credential query parameters, and leaves the rest of the URL readable", () => {
    const out = redact("https://api.example.com/v1/docs?access_token=abcd1234&page=2");
    expect(out).not.toContain("abcd1234");
    expect(out).toContain("page=2");
    expect(out).toContain("api.example.com/v1/docs");
  });

  it("strips an Authorization header a site echoed back", () => {
    const out = redact('{"yourRequest":{"headers":{"Authorization":"Bearer abcdef0123456789"}}}');
    expect(out).not.toContain("abcdef0123456789");
    expect(out).toContain("<redacted>");
  });

  it("strips a raw header dump and cookies", () => {
    const out = redact("Authorization: Bearer zzzzzzzzzzzz\nSet-Cookie: SID=yyyyyyyyyy\nAccept: */*");
    expect(out).not.toContain("zzzzzzzzzzzz");
    expect(out).not.toContain("SID=yyyyyyyyyy");
    expect(out).toContain("Accept: */*");
  });

  it("strips token values in a JSON body", () => {
    const out = redact('{"access_token":"aaaa","refresh_token":"bbbb","client_secret":"cccc","ok":false}');
    for (const secret of ["aaaa", "bbbb", "cccc"]) expect(out).not.toContain(secret);
    expect(out).toContain('"ok":false');
  });

  it("leaves an ordinary error body exactly as it was", () => {
    const body = '{"error":"not_found","message":"No page at /missing"}';
    expect(redact(body)).toBe(body);
  });
});

describe("shape (rules 2 and 4)", () => {
  it("puts the code first, then the literal status line", () => {
    const text = formatEnvelope("http_403", "Could not read it: no access.", "HTTP 403 Forbidden", "{}");
    expect(text.split("\n")[0]).toBe("[http_403] Could not read it: no access.");
    expect(text.split("\n")[1]).toBe("HTTP 403 Forbidden");
  });

  it("omits the status line when the failure was not HTTP", () => {
    expect(formatEnvelope("timeout", "Could not fetch the page: no answer.")).not.toContain("HTTP ");
  });

  it("caps the body and says so", () => {
    const text = formatEnvelope("http_500", "Could not fetch the page: it failed.", "HTTP 500 x", "y".repeat(5000));
    const body = text.split("\n").slice(2).join("\n");
    expect(body.endsWith(TRUNCATION_SUFFIX)).toBe(true);
    expect(body.length).toBe(BODY_LIMIT + TRUNCATION_SUFFIX.length);
  });

  it("keeps line 1 on one line", () => {
    expect(formatEnvelope("bad_request", "Could not do it:\nsomething\nwrapped.")).toBe(
      "[bad_request] Could not do it: something wrapped.",
    );
  });

  it("omits the reason phrase rather than inventing one", () => {
    expect(statusLine(404, undefined)).toBe("HTTP 404");
    expect(statusLine(404, "Not Found")).toBe("HTTP 404 Not Found");
  });
});

describe("transport classification (rule 4, from the other side)", () => {
  const cases: [string, string][] = [
    ["ECONNREFUSED", "connection_refused"],
    ["ENOTFOUND", "dns_failure"],
    ["EAI_AGAIN", "dns_failure"],
    ["UND_ERR_CONNECT_TIMEOUT", "timeout"],
    ["CERT_HAS_EXPIRED", "tls_error"],
    ["ERR_TLS_CERT_ALTNAME_INVALID", "tls_error"],
    ["ECONNRESET", "network_error"],
  ];

  for (const [code, expected] of cases) {
    it(`reads ${code} off the cause chain as ${expected}`, () => {
      const failure = transportFailure(nodeFetchFailure(code), "https://example.com");
      expect(failure.code).toBe(expected);
      expect(failure.line).toBeNull();
    });
  }

  it("finds the code inside an AggregateError, which is where Node hides it", () => {
    const inner = Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" });
    const aggregate = Object.assign(new AggregateError([inner], "All attempts failed"), {});
    const outer = new TypeError("fetch failed");
    (outer as { cause?: unknown }).cause = aggregate;
    expect(transportFailure(outer, "https://example.com").code).toBe("connection_refused");
  });

  it("redacts the URL it echoes when nothing classifies", () => {
    const failure = transportFailure(new Error("something odd"), "https://alex:hunter2@example.com");
    expect(failure.reason).not.toContain("hunter2");
    expect(failure.code).toBe("network_error");
  });
});

describe("HTTP failures keep the site's own words", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    globalThis.fetch = mockFetch as any;
    Fetcher.hasYtDlp = false;
    dns.promises.lookup = (async () => ({ address: "93.184.216.34", family: 4 })) as any;
  });

  it("401: status line and verbatim body, both of which used to be thrown away", async () => {
    const body = '{"error":"invalid_token","error_description":"The access token expired"}';
    mockFetch.mockResolvedValueOnce(response(401, body, "Unauthorized"));

    const result = await Fetcher.html({ url: "https://example.com" });
    const lines = result.content[0].text.split("\n");

    expect(result.isError).toBe(true);
    expect(lines[0]).toBe("[http_401] Could not fetch the page: the site refused the request as unauthenticated.");
    expect(lines[1]).toBe("HTTP 401 Unauthorized");
    expect(lines.slice(2).join("\n")).toBe(body);
  });

  it("403: the body separates a revoked key from a key that never had access", async () => {
    const body = '{"reason":"this key is not authorised for that document"}';
    mockFetch.mockResolvedValueOnce(response(403, body, "Forbidden"));

    const result = await Fetcher.json({ url: "https://example.com" });
    expect(result.content[0].text).toContain(body);
    expect(result.content[0].text).toStartWith("[http_403] ");
  });

  it("429: still an envelope, still the body", async () => {
    mockFetch.mockResolvedValueOnce(response(429, "slow down", "Too Many Requests"));
    const result = await Fetcher.markdown({ url: "https://example.com" });
    expect(result.content[0].text.split("\n")).toEqual([
      "[http_429] Could not fetch the page as Markdown: the site is rate limiting this client.",
      "HTTP 429 Too Many Requests",
      "slow down",
    ]);
  });

  it("redacts a credential the site echoed back inside its error body", async () => {
    const leaky = '{"yourRequest":{"headers":{"Authorization":"Bearer abcdef0123456789"}},"error":"bad"}';
    mockFetch.mockResolvedValueOnce(response(400, leaky, "Bad Request"));

    const result = await Fetcher.html({ url: "https://example.com" });
    expect(result.content[0].text).not.toContain("abcdef0123456789");
    expect(result.content[0].text).toContain("<redacted>");
    expect(result.content[0].text).toContain('"error":"bad"');
  });

  it("a 200 that is not JSON fails, with the body as the evidence", async () => {
    mockFetch.mockResolvedValueOnce(response(200, "<html>login page</html>", "OK"));
    const result = await Fetcher.json({ url: "https://example.com" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toStartWith("[invalid_response] ");
    expect(result.content[0].text).toContain("<html>login page</html>");
  });

  it("never invents a status line for a failure that had no response", async () => {
    mockFetch.mockRejectedValueOnce(nodeFetchFailure("ECONNREFUSED"));
    const result = await Fetcher.html({ url: "https://example.com" });
    expect(result.content[0].text).toStartWith("[connection_refused] ");
    expect(result.content[0].text).not.toContain("HTTP ");
  });
});

describe("a real transport failure, with no mock in the way", () => {
  beforeEach(() => {
    globalThis.fetch = originalFetch;
    dns.promises.lookup = originalLookup;
    Fetcher.hasYtDlp = false;
  });

  // The exact code depends on the runtime, and that is worth writing down rather than papering
  // over: Node reports ENOTFOUND for an unresolvable host (so this is dns_failure in the shipped
  // bundle, which runs on Node), while Bun, the test runner, reports ConnectionRefused for the same
  // request. What both must satisfy is the CONTRACT: a transport code, and no invented status line.
  const TRANSPORT_CODES = [
    "connection_refused",
    "dns_failure",
    "tls_error",
    "timeout",
    "network_error",
  ];

  it("an unresolvable host fails with a transport code and no status line", async () => {
    const url = `https://no-such-host-${Date.now()}.invalid/page`;
    const result = await Fetcher.html({ url });
    const code = result.content[0].text.match(/^\[([a-z_]+)\]/)?.[1];

    expect(result.isError).toBe(true);
    expect(TRANSPORT_CODES).toContain(code);
    expect(result.content[0].text).not.toContain("HTTP ");
    expect(result.content[0].text.split("\n").length).toBeGreaterThan(1);
  });
});

describe("an error is never parked behind a circuit handle (rule 2)", () => {
  // A LIVE circuit endpoint, not a dead port. Pointing at a closed port makes this test pass whether
  // or not the guard exists, because wrapResult treats an unreachable buffer as a no-op: the first
  // version of this test could not fail.
  async function withCircuit<T>(run: () => Promise<T>): Promise<T> {
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ slug: "@@h7@@", payload: "" }));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as { port: number };
    process.env.MAESTRO_CIRCUIT_URL = `http://127.0.0.1:${port}`;
    process.env.MAESTRO_CIRCUIT_SECRET = "secret";
    process.env.MAESTRO_SESSION_ID = "session";
    try {
      return await run();
    } finally {
      delete process.env.MAESTRO_CIRCUIT_URL;
      delete process.env.MAESTRO_CIRCUIT_SECRET;
      delete process.env.MAESTRO_SESSION_ID;
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }

  const longText = (prefix: string) => prefix + "x".repeat(400);

  it("parks a long SUCCESS, which is the behaviour worth keeping", async () => {
    const wrapped = await withCircuit(() =>
      wrapResult({ content: [{ type: "text", text: longText("a long page ") }], isError: false }),
    );
    expect(wrapped.content[0].text).toStartWith("[circuit @@h7@@");
  });

  it("leaves a long FAILURE alone, so the code stays first", async () => {
    const wrapped = await withCircuit(() =>
      wrapResult({
        content: [{ type: "text", text: longText("[http_500] Could not fetch the page: it failed.\n") }],
        isError: true,
      }),
    );
    expect(wrapped.content[0].text).toStartWith("[http_500] ");
    expect(wrapped.content[0].text).not.toContain("[circuit ");
  });
});

describe("over the real MCP wire", () => {
  async function callTool(name: string, args: Record<string, unknown>) {
    const client = new Client({ name: "envelope-test", version: "0" }, { capabilities: {} });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [new URL("./index.ts", import.meta.url).pathname],
    });
    await client.connect(transport);
    try {
      return (await client.callTool({ name, arguments: args })) as {
        isError?: boolean;
        content: { text: string }[];
      };
    } finally {
      await client.close();
    }
  }

  it("an unknown tool is an isError result, not a protocol error", async () => {
    const result = await callTool("fetch_moon", { url: "https://example.com" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toStartWith("[not_found] ");
  }, 30000);

  it("a rejected argument is a bad_request with zod's own account below it", async () => {
    const result = await callTool("fetch_html", { url: "not a url" });
    expect(result.isError).toBe(true);
    const lines = result.content[0].text.split("\n");
    expect(lines[0]).toBe("[bad_request] Could not fetch the page: the arguments were rejected.");
    expect(lines.slice(1).join("\n")).toContain("url");
    expect(result.content[0].text).not.toContain("HTTP ");
  }, 30000);
});
