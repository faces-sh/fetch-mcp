#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { RequestPayloadSchema, YouTubeTranscriptPayloadSchema } from "./types.js";
import { Fetcher } from "./Fetcher.js";
import { CircuitError, resolveArgs, wrapResult } from "./circuitBuffer.js";
import { envelopeResult, oneLine, resultFor } from "./envelope.js";
import process from "process";
import { downloadLimit } from "./types.js";
import pkg from "../package.json" with { type: "json" };

const server = new Server(
  {
    name: "zcaceres/fetch",
    version: pkg.version,
  },
  {
    capabilities: {
      resources: {},
      tools: {},
    },
  },
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "fetch_html",
        description: "Fetch a website and return its unmodified contents as HTML",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "URL of the website to fetch",
            },
            headers: {
              type: "object",
              description: "Optional headers to include in the request",
            },
            max_length: {
              type: "number",
              description: `Maximum number of characters to return (default: ${downloadLimit})`,
            },
            start_index: {
              type: "number",
              description: "Start content from this character index (default: 0)",
            },
            proxy: {
              type: "string",
              description: "Optional proxy URL (e.g. 'http://proxy:8080')",
            },
          },
          required: ["url"],
        },
      },
      {
        name: "fetch_markdown",
        description: "Fetch a website and return its contents converted to Markdown",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "URL of the website to fetch",
            },
            headers: {
              type: "object",
              description: "Optional headers to include in the request",
            },
            max_length: {
              type: "number",
              description: `Maximum number of characters to return (default: ${downloadLimit})`,
            },
            start_index: {
              type: "number",
              description: "Start content from this character index (default: 0)",
            },
            proxy: {
              type: "string",
              description: "Optional proxy URL (e.g. 'http://proxy:8080')",
            },
          },
          required: ["url"],
        },
      },
      {
        name: "fetch_txt",
        description:
          "Fetch a website, convert the content to plain text (no HTML)",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "URL of the website to fetch",
            },
            headers: {
              type: "object",
              description: "Optional headers to include in the request",
            },
            max_length: {
              type: "number",
              description: `Maximum number of characters to return (default: ${downloadLimit})`,
            },
            start_index: {
              type: "number",
              description: "Start content from this character index (default: 0)",
            },
            proxy: {
              type: "string",
              description: "Optional proxy URL (e.g. 'http://proxy:8080')",
            },
          },
          required: ["url"],
        },
      },
      {
        name: "fetch_json",
        description: "Fetch a JSON file from a URL",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "URL of the JSON to fetch",
            },
            headers: {
              type: "object",
              description: "Optional headers to include in the request",
            },
            max_length: {
              type: "number",
              description: `Maximum number of characters to return (default: ${downloadLimit})`,
            },
            start_index: {
              type: "number",
              description: "Start content from this character index (default: 0)",
            },
            proxy: {
              type: "string",
              description: "Optional proxy URL (e.g. 'http://proxy:8080')",
            },
          },
          required: ["url"],
        },
      },
      {
        name: "fetch_readable",
        description:
          "Fetch a website and return its main content parsed by Mozilla Readability, converted to Markdown. Strips away navigation, ads, and boilerplate. Ideal for articles and blog posts.",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "URL of the website to fetch",
            },
            headers: {
              type: "object",
              description: "Optional headers to include in the request",
            },
            max_length: {
              type: "number",
              description: `Maximum number of characters to return (default: ${downloadLimit})`,
            },
            start_index: {
              type: "number",
              description: "Start content from this character index (default: 0)",
            },
            proxy: {
              type: "string",
              description: "Optional proxy URL (e.g. 'http://proxy:8080')",
            },
          },
          required: ["url"],
        },
      },
      {
        name: "fetch_youtube_transcript",
        description:
          "Fetch a YouTube video page and extract its captions/transcript",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "URL of the YouTube video",
            },
            headers: {
              type: "object",
              description: "Optional headers to include in the request",
            },
            max_length: {
              type: "number",
              description: `Maximum number of characters to return (default: ${downloadLimit})`,
            },
            start_index: {
              type: "number",
              description: "Start content from this character index (default: 0)",
            },
            proxy: {
              type: "string",
              description: "Optional proxy URL (e.g. 'http://proxy:8080')",
            },
            lang: {
              type: "string",
              description: "Language code for captions (default: 'en')",
            },
          },
          required: ["url"],
        },
      },
    ],
  };
});

const FETCH_TOOLS = new Set(["fetch_html", "fetch_json", "fetch_txt", "fetch_markdown", "fetch_readable"]);

const ACTIONS: Record<string, string> = {
  fetch_html: "fetch the page",
  fetch_json: "fetch the JSON",
  fetch_txt: "fetch the page as text",
  fetch_markdown: "fetch the page as Markdown",
  fetch_readable: "read the article",
  fetch_youtube_transcript: "fetch the transcript",
};

// Everything the handler can throw leaves as the envelope, isError set (rule 1). It used to throw,
// which the MCP SDK turns into a JSON-RPC error rather than a tool result: the caller then sees a
// protocol failure with no code in it, which is exactly the shape this contract exists to remove.
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name } = request.params;
  const action = ACTIONS[name] ?? "do that";
  try {
    // Circuit: expand any @@hN@@ handle in the args before validation (Maestro's handle bus, no-op
    // without the env), then park a large fetched result behind a handle on the way out so the next
    // tool can wire it.
    const args = await resolveArgs(request.params.arguments ?? {});

    if (name === "fetch_youtube_transcript") {
      const validatedArgs = YouTubeTranscriptPayloadSchema.parse(args);
      return await wrapResult(await Fetcher.youtubeTranscript(validatedArgs));
    }

    if (!FETCH_TOOLS.has(name)) {
      return envelopeResult("not_found", `Could not run "${name}": this server has no such tool.`);
    }

    const validatedArgs = RequestPayloadSchema.parse(args);

    if (name === "fetch_html") return await wrapResult(await Fetcher.html(validatedArgs));
    if (name === "fetch_json") return await wrapResult(await Fetcher.json(validatedArgs));
    if (name === "fetch_txt") return await wrapResult(await Fetcher.txt(validatedArgs));
    if (name === "fetch_markdown") return await wrapResult(await Fetcher.markdown(validatedArgs));
    return await wrapResult(await Fetcher.readable(validatedArgs));
  } catch (error) {
    if (error instanceof CircuitError) {
      return envelopeResult("handle_expired", `Could not ${action}: ${oneLine(error.message)}`);
    }
    if (isSchemaError(error)) {
      return envelopeResult(
        "bad_request",
        `Could not ${action}: the arguments were rejected.`,
        null,
        describeSchemaError(error),
      );
    }
    return resultFor(error, action);
  }
});

/** A zod rejection, recognised without importing zod's internals. */
function isSchemaError(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && Array.isArray((error as { issues?: unknown }).issues));
}

/** Zod's own account of what was wrong, reproduced rather than paraphrased. */
function describeSchemaError(error: unknown): string {
  const issues = (error as { issues: { path?: unknown[]; message?: string }[] }).issues;
  return issues
    .map((issue) => `${(issue.path ?? []).join(".") || "(root)"}: ${issue.message ?? "invalid"}`)
    .join("\n");
}

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});
