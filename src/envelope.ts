// The uniform failure envelope every tool result carries when something goes wrong.
//
// Contract (Maestro's docs/MCP_FAILURE_ENVELOPE.md):
//
//   [<code>] <one plain sentence: what did not happen>
//   HTTP <status> <reason phrase>
//   <the provider's response body, verbatim>
//
// Line 1 is for a person and for the model. Lines 2 and 3 are the evidence. The status line
// appears only when there really was an HTTP response; a transport failure carries a snake_case
// code and no status line, because inventing a status would be a lie. The body is whatever the
// site returned, byte for byte, with credentials struck out and nothing else touched: deciding
// what a 403 MEANS is the caller's job, and this server does not know whose credential it was.

export const BODY_LIMIT = 4000;
export const TRUNCATION_SUFFIX = " ...[truncated]";
export const REDACTED = "<redacted>";

// How much of an error response to read before giving up. Generous enough that a real API error
// arrives whole, small enough that a hostile megabyte does not.
export const ERROR_BODY_READ_LIMIT = 16384;

// Keys whose VALUE is a credential wherever it appears (rule 8).
const SECRET_KEYS = [
  "access_token",
  "refresh_token",
  "session_token",
  "id_token",
  "client_secret",
  "api_key",
  "apikey",
  "auth_token",
  "password",
  "token",
];
// Query parameters that carry a credential in a URL. `key` and `sig` are here because that is what
// Google and S3-style signed URLs call theirs, and this server echoes the URL in every failure.
const SECRET_PARAMS = [...SECRET_KEYS, "auth", "key", "signature", "sig", "sas"];
const SECRET_HEADERS = [
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-auth-token",
  "x-api-key",
];

const alt = (values: string[]) => values.map((v) => v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");

// `Authorization: Bearer x` on its own line (a raw header dump).
const HEADER_LINE_RE = new RegExp(`^([ \\t]*(?:${alt(SECRET_HEADERS)})[ \\t]*:[ \\t]*).*$`, "gim");
// `"Authorization": "Bearer x"` inside JSON (an echo service repeating the request).
const HEADER_JSON_RE = new RegExp(`("(?:${alt(SECRET_HEADERS)})"\\s*:\\s*)"(?:[^"\\\\]|\\\\.)*"`, "gi");
// `"access_token": "x"` inside JSON.
const JSON_SECRET_RE = new RegExp(`("(?:${alt(SECRET_KEYS)})"\\s*:\\s*)"(?:[^"\\\\]|\\\\.)*"`, "gi");
// `access_token=x` in a URL, a query string, or a form body.
const QUERY_SECRET_RE = new RegExp(`\\b((?:${alt(SECRET_PARAMS)})=)[^&\\s"'<>]+`, "gi");
// `https://user:pass@host` — the credential is in the URL itself.
const USERINFO_RE = /\b([a-z][a-z0-9+.-]*:\/\/)[^/\s:@]+:[^/\s@]+@/gi;
// A bare credential after its scheme, anywhere.
const SCHEME_RE = /\b(Bearer|Basic|Token)\s+[A-Za-z0-9\-._~+/=]{8,}/gi;

/**
 * Strike credentials out of text that is otherwise reproduced verbatim.
 *
 * Every failure from this server echoes a URL, and a URL is a credential-bearing string: it can
 * carry userinfo and it can carry a signed-token query parameter. The response body is echoed too,
 * and a site that repeats your request back to you repeats your Authorization header with it.
 */
export function redact(text: string): string {
  if (!text) return text;
  return text
    .replace(HEADER_LINE_RE, `$1${REDACTED}`)
    .replace(HEADER_JSON_RE, `$1"${REDACTED}"`)
    .replace(JSON_SECRET_RE, `$1"${REDACTED}"`)
    .replace(USERINFO_RE, `$1${REDACTED}@`)
    .replace(QUERY_SECRET_RE, `$1${REDACTED}`)
    .replace(SCHEME_RE, `$1 ${REDACTED}`);
}

/** Cap an echoed body at the contract's 4000 characters. */
export function truncate(text: string): string {
  return text.length <= BODY_LIMIT ? text : text.slice(0, BODY_LIMIT) + TRUNCATION_SUFFIX;
}

/** Build the literal status line for a real HTTP response. */
export function statusLine(status: number, statusText?: string | null): string {
  const reason = (statusText ?? "").trim();
  return reason ? `HTTP ${status} ${reason}` : `HTTP ${status}`;
}

/** Keep line 1 to one line, so the code that leads it is the first thing a reader sees. */
export function oneLine(text: string): string {
  return text.split(/\s+/).filter(Boolean).join(" ");
}

/** Assemble the three-line envelope. */
export function formatEnvelope(
  code: string,
  sentence: string,
  line?: string | null,
  body?: string | null,
): string {
  const lines = [`[${code}] ${oneLine(sentence)}`];
  if (line) lines.push(line);
  if (body) {
    const evidence = truncate(redact(body));
    if (evidence) lines.push(evidence);
  }
  return lines.join("\n");
}

export type ToolResult = {
  content: { type: string; text: string }[];
  isError: boolean;
};

/** The MCP result shape for a failure: isError is the contract, the text is the backstop. */
export function envelopeResult(
  code: string,
  sentence: string,
  line?: string | null,
  body?: string | null,
): ToolResult {
  return {
    content: [{ type: "text", text: formatEnvelope(code, sentence, line, body) }],
    isError: true,
  };
}

/**
 * A failure that already knows its own envelope. Thrown deep (inside _fetch) and caught at the
 * tool boundary, so the code, the status line and the body survive the whole way up instead of
 * being flattened into a sentence somebody later has to parse.
 */
export class FetchFailure extends Error {
  readonly code: string;
  readonly reason: string;
  readonly line: string | null;
  readonly body: string | null;

  constructor(code: string, reason: string, line?: string | null, body?: string | null) {
    super(`[${code}] ${reason}`);
    this.name = "FetchFailure";
    this.code = code;
    this.reason = reason;
    this.line = line ?? null;
    this.body = body ?? null;
  }

  /** Render as the tool result, naming the act that did not happen. */
  toResult(action: string): ToolResult {
    return envelopeResult(this.code, `Could not ${action}: ${this.reason}`, this.line, this.body);
  }
}

// What a transport failure's own error code means, in plain words. Descriptions of what happened,
// never advice about what to do next: this server does not know whether the caller can fix it.
const TRANSPORT_CODES: Record<string, [string, string]> = {
  ECONNREFUSED: ["connection_refused", "nothing accepted a connection at that address."],
  CONNECTIONREFUSED: ["connection_refused", "nothing accepted a connection at that address."],
  ENOTFOUND: ["dns_failure", "the address did not resolve."],
  EAI_AGAIN: ["dns_failure", "the address could not be looked up."],
  DNSERROR: ["dns_failure", "the address did not resolve."],
  ETIMEDOUT: ["timeout", "the site did not answer in time."],
  UND_ERR_CONNECT_TIMEOUT: ["timeout", "the site did not answer in time."],
  UND_ERR_HEADERS_TIMEOUT: ["timeout", "the site did not answer in time."],
  UND_ERR_BODY_TIMEOUT: ["timeout", "the site stopped sending before it finished."],
  CERT_HAS_EXPIRED: ["tls_error", "the site's certificate has expired."],
  DEPTH_ZERO_SELF_SIGNED_CERT: ["tls_error", "the site's certificate is not trusted."],
  SELF_SIGNED_CERT_IN_CHAIN: ["tls_error", "the site's certificate is not trusted."],
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: ["tls_error", "the site's certificate could not be verified."],
  ERR_TLS_CERT_ALTNAME_INVALID: ["tls_error", "the site's certificate is for a different host."],
  ERR_SSL_WRONG_VERSION_NUMBER: ["tls_error", "the TLS handshake failed."],
  ECONNRESET: ["network_error", "the connection was reset before the site answered."],
  EPIPE: ["network_error", "the connection closed before the site answered."],
  UND_ERR_SOCKET: ["network_error", "the connection dropped before the site answered."],
  ABORTERROR: ["timeout", "the request was aborted before the site answered."],
};

const CAUSE_CHAIN_LIMIT = 8;

/** Collect every `code` in an error's cause chain, including an AggregateError's members. */
function errorCodes(err: unknown): string[] {
  const codes: string[] = [];
  const seen = new Set<unknown>();
  const visit = (value: unknown, depth: number): void => {
    if (!value || typeof value !== "object" || depth > CAUSE_CHAIN_LIMIT || seen.has(value)) return;
    seen.add(value);
    const candidate = value as { code?: unknown; name?: unknown; cause?: unknown; errors?: unknown };
    if (typeof candidate.code === "string") codes.push(candidate.code.toUpperCase());
    if (typeof candidate.name === "string") codes.push(candidate.name.toUpperCase());
    if (Array.isArray(candidate.errors)) {
      for (const member of candidate.errors) visit(member, depth + 1);
    }
    visit(candidate.cause, depth + 1);
  };
  visit(err, 0);
  return codes;
}

/**
 * Classify a request that never produced an HTTP response.
 *
 * Reads the error CODE off the cause chain rather than its words: Node buries the real cause two
 * levels down under a flat "fetch failed", and an AggregateError hides several of them in a list.
 * The message is only consulted as a last resort, and only for the two cases that have no code.
 */
export function transportFailure(err: unknown, url: string): FetchFailure {
  const detail = err instanceof Error ? err.message : String(err);
  const evidence = describeCause(err);

  for (const code of errorCodes(err)) {
    const known = TRANSPORT_CODES[code];
    if (known) return new FetchFailure(known[0], known[1], null, evidence);
  }

  const words = `${detail} ${evidence}`.toLowerCase();
  if (words.includes("certificate") || words.includes("ssl") || words.includes("tls")) {
    return new FetchFailure("tls_error", "the secure connection to the site could not be established.", null, evidence);
  }
  if (words.includes("getaddrinfo") || words.includes("dns")) {
    return new FetchFailure("dns_failure", "the address did not resolve.", null, evidence);
  }
  if (words.includes("timeout") || words.includes("timed out")) {
    return new FetchFailure("timeout", "the site did not answer in time.", null, evidence);
  }
  return new FetchFailure("network_error", `the request to ${redact(url)} never reached the site.`, null, evidence);
}

/** The underlying failure's own words, reproduced rather than paraphrased. */
function describeCause(err: unknown): string {
  const parts: string[] = [];
  const seen = new Set<unknown>();
  let cursor: unknown = err;
  for (let depth = 0; cursor && depth < CAUSE_CHAIN_LIMIT; depth++) {
    if (seen.has(cursor)) break;
    seen.add(cursor);
    if (cursor instanceof Error) {
      parts.push(cursor.message);
      const members = (cursor as unknown as { errors?: unknown }).errors;
      if (Array.isArray(members)) {
        for (const member of members) {
          if (member instanceof Error) parts.push(member.message);
        }
      }
    } else if (typeof cursor === "string") {
      parts.push(cursor);
    }
    cursor = (cursor as { cause?: unknown })?.cause;
  }
  return [...new Set(parts.filter(Boolean))].join(": ");
}

/**
 * Render any failure as the envelope, whatever it turned out to be.
 *
 * A FetchFailure already knows its shape. Anything else is a bug or a library throwing, and gets
 * an honest internal_error rather than a guess about what it meant.
 */
export function resultFor(err: unknown, action: string): ToolResult {
  if (err instanceof FetchFailure) return err.toResult(action);
  const detail = err instanceof Error ? err.message : String(err);
  return envelopeResult("internal_error", `Could not ${action}: ${oneLine(detail) || "something went wrong."}`);
}
