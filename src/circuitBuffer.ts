// The TypeScript half of Maestro's circuit cache (docs/reqs/003_handle_bus.md). Mirrors the Python helper
// (Resources/dispatch/bin/circuit_buffer.py); both satisfy the same shared test vector
// (scripts/test_circuit_helper.py). Applied at the server's central tool-call handler:
//   resolveArgs(args) at the top (expand @@hN@@ slugs back into payloads, BEFORE validation),
//   wrapResult(result) on return (park a large result + PREPEND its slug so the next tool can wire it).
// No-op when the circuit env is absent (server run outside Maestro), so the server still works solo.

const THRESHOLD = 200;

export class CircuitError extends Error {}

function cfg(): { url: string; secret: string; session: string } | null {
  const url = (process.env.MAESTRO_CIRCUIT_URL || "").trim();
  const secret = (process.env.MAESTRO_CIRCUIT_SECRET || "").trim();
  const session = (process.env.MAESTRO_SESSION_ID || "").trim();
  return url && secret && session ? { url, secret, session } : null;
}

async function post(path: string, body: unknown, url: string, secret: string): Promise<{ status: number; json: any }> {
  const r = await fetch(url.replace(/\/$/, "") + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Circuit-Secret": secret },
    body: JSON.stringify(body),
  });
  return { status: r.status, json: r.status === 200 ? await r.json() : null };
}

async function fetchSlug(slug: string, c: { url: string; secret: string; session: string }): Promise<string> {
  const { status, json } = await post("/get", { session: c.session, slug }, c.url, c.secret);
  if (status === 404) {
    throw new CircuitError(`Unknown or expired circuit slug ${slug}; it is no longer cached, re-fetch it.`);
  }
  return (json && json.payload) || "";
}

export async function resolveArgs(args: any): Promise<any> {
  const c = cfg();
  if (!c) return args;
  const expand = async (v: any): Promise<any> => {
    if (typeof v === "string" && /@@h\d+@@/.test(v)) {
      const tokens = new Set((v.match(/@@h\d+@@/g) || []));
      let out = v;
      for (const t of tokens) {
        const payload = await fetchSlug(t, c);
        out = out.split(t).join(payload);
      }
      return out;
    }
    if (Array.isArray(v)) return Promise.all(v.map(expand));
    if (v && typeof v === "object") {
      const o: Record<string, unknown> = {};
      for (const k of Object.keys(v)) o[k] = await expand(v[k]);
      return o;
    }
    return v;
  };
  return expand(args);
}

export async function wrapResult(result: any): Promise<any> {
  const c = cfg();
  if (!c || !result || !Array.isArray(result.content)) return result;
  const first = result.content[0];
  if (!first || first.type !== "text" || typeof first.text !== "string" || first.text.length < THRESHOLD) {
    return result;
  }
  let slug: string | undefined;
  try {
    const { json } = await post("/put", { session: c.session, payload: first.text }, c.url, c.secret);
    slug = json && json.slug;
  } catch {
    return result; // best-effort: a buffer hiccup never breaks the tool
  }
  if (!slug) return result;
  const tag = `[circuit ${slug} · to feed this whole result into another tool, pass ${slug} as its argument ` +
    `instead of retyping it; read_tool_result(${slug}) shows it in full later]`;
  return { ...result, content: [{ ...first, text: tag + "\n\n" + first.text }, ...result.content.slice(1)] };
}
