import { JSDOM } from "jsdom";
import TurndownService from "turndown";
import { Readability } from "@mozilla/readability";
import is_ip_private from "private-ip";
import dns from "node:dns";
import { RequestPayload, YouTubeTranscriptPayload, downloadLimit, maxResponseBytes } from "./types.js";
import { YouTubeTranscript } from "./YouTubeTranscript.js";
import {
  ERROR_BODY_READ_LIMIT,
  FetchFailure,
  redact,
  resultFor,
  statusLine,
  transportFailure,
} from "./envelope.js";

export class Fetcher {
  private static applyLengthLimits(text: string, maxLength: number, startIndex: number): string {
    if (startIndex >= text.length) {
      return "";
    }

    const end = maxLength > 0 ? Math.min(startIndex + maxLength, text.length) : text.length;
    return text.substring(startIndex, end);
  }

  private static validateUrl(url: string): void {
    const parsedUrl = new URL(url);
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      throw new FetchFailure(
        "blocked_url",
        `the URL has a disallowed protocol "${parsedUrl.protocol}". Only HTTP and HTTPS are allowed.`,
      );
    }
    const hostname = parsedUrl.hostname;
    const bareHostname = hostname.startsWith('[') && hostname.endsWith(']')
      ? hostname.slice(1, -1)
      : hostname;
    if (bareHostname === 'localhost' || is_ip_private(bareHostname)) {
      throw new FetchFailure(
        "blocked_private_address",
        `the request was to private address "${bareHostname}". This prevents SSRF attacks where a local MCP server could access privileged internal services.`,
      );
    }
  }

  private static async validateResolvedIp(url: string): Promise<void> {
    const hostname = new URL(url).hostname;
    const bareHostname = hostname.startsWith('[') && hostname.endsWith(']')
      ? hostname.slice(1, -1)
      : hostname;
    try {
      const { address } = await dns.promises.lookup(bareHostname);
      if (is_ip_private(address)) {
        throw new FetchFailure(
          "blocked_private_address",
          `hostname "${bareHostname}" resolved to private IP "${address}". This prevents DNS rebinding SSRF attacks.`,
        );
      }
    } catch (e) {
      if (e instanceof FetchFailure) throw e;
      // DNS lookup failures (e.g. non-resolvable hostnames) are not SSRF - let fetch handle them
    }
  }

  private static async _fetch({
    url,
    headers,
    proxy,
  }: RequestPayload): Promise<Response> {
    this.validateUrl(url);
    await this.validateResolvedIp(url);
    let response: Response;
    try {
      response = await fetch(url, {
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          ...headers,
        },
        // Note: proxy is a Bun-specific fetch option. On Node.js, this option is silently ignored.
        // To use a proxy on Node.js, you would need an HTTP agent library like http-proxy-agent.
        ...(proxy ? { proxy } : {}),
      } as RequestInit);
    } catch (e: unknown) {
      if (e instanceof FetchFailure) throw e;
      // No HTTP response happened here, so there is no status line to carry (rule 4). The code
      // says which of the four cases it was and the underlying error's own words are the evidence.
      throw transportFailure(e, url);
    }

    if (response.url && response.url !== url) {
      this.validateUrl(response.url);
      await this.validateResolvedIp(response.url);
    }

    if (!response.ok) {
      // The body is the ONLY thing that separates an expired key from a key that never had access,
      // and this used to throw it away and keep the number. It travels with the failure now,
      // uninterpreted, for whoever can actually act on it.
      const body = await this.readErrorBody(response);
      throw new FetchFailure(
        `http_${response.status}`,
        this.httpReason(response.status),
        statusLine(response.status, (response as { statusText?: string }).statusText),
        body,
      );
    }

    const contentLength = response.headers?.get?.("content-length");
    if (contentLength && parseInt(contentLength, 10) > maxResponseBytes) {
      throw new FetchFailure(
        "response_too_large",
        `the response is ${contentLength} bytes, over the ${maxResponseBytes} byte limit.`,
        statusLine(response.status, (response as { statusText?: string }).statusText),
      );
    }

    return response;
  }

  // What the four-hundreds and five-hundreds MEAN in plain words. Descriptions of what happened,
  // never advice about what to do next (rule 7): this server does not know whose credential it was,
  // nor whether the caller can do anything about it.
  private static readonly HTTP_REASONS: Record<number, string> = {
    400: "the site rejected the request as malformed.",
    401: "the site refused the request as unauthenticated.",
    403: "the site refused access to that page.",
    404: "the site has no page at that address.",
    405: "the site does not allow that method on this resource.",
    408: "the site timed out waiting for the request.",
    410: "the page is gone from the site.",
    429: "the site is rate limiting this client.",
    451: "the site refused the page for legal reasons.",
    500: "the site failed while producing the page.",
    502: "the site got a bad answer from upstream.",
    503: "the site is unavailable.",
    504: "the site timed out upstream.",
  };

  private static httpReason(status: number): string {
    const known = this.HTTP_REASONS[status];
    if (known) return known;
    if (status >= 500) return "the site failed.";
    if (status >= 400) return "the site rejected the request.";
    return "the site answered with something that could not be used.";
  }

  /**
   * Read an error response's body, bounded.
   *
   * Bounded because a failing site is exactly the one likely to answer with a megabyte of HTML,
   * and this is the unhappy path: nothing here should be able to hang or exhaust memory. What
   * comes back is the site's own words, uninterpreted, and it is capped again at 4000 characters
   * when the envelope is assembled.
   */
  private static async readErrorBody(response: Response): Promise<string> {
    try {
      if (!response.body) {
        const text = await response.text?.();
        return typeof text === "string" ? text.slice(0, ERROR_BODY_READ_LIMIT) : "";
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let text = "";
      try {
        while (text.length < ERROR_BODY_READ_LIMIT) {
          const { done, value } = await reader.read();
          if (done) break;
          text += decoder.decode(value, { stream: true });
        }
        text += decoder.decode();
      } finally {
        reader.cancel();
      }
      return text.slice(0, ERROR_BODY_READ_LIMIT);
    } catch {
      // A body we cannot read is no reason to lose the status we already have. The envelope
      // simply carries no third line, which is honest: there was nothing to reproduce.
      return "";
    }
  }

  private static async readResponseText(response: Response): Promise<string> {
    if (!response.body) return response.text();
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let result = "";
    let bytesRead = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        bytesRead += value.byteLength;
        if (bytesRead > maxResponseBytes) {
          throw new FetchFailure(
            "response_too_large",
            `the response went over the ${maxResponseBytes} byte limit while being read.`,
          );
        }
        result += decoder.decode(value, { stream: true });
      }
      result += decoder.decode();
      return result;
    } finally {
      reader.cancel();
    }
  }

  static async html(requestPayload: RequestPayload) {
    try {
      const response = await this._fetch(requestPayload);
      let html = await this.readResponseText(response);
      
      // Apply length limits
      html = this.applyLengthLimits(
        html, 
        requestPayload.max_length ?? downloadLimit,
        requestPayload.start_index ?? 0
      );

      return { content: [{ type: "text", text: html }], isError: false };
    } catch (error) {
      return resultFor(error, "fetch the page");
    }
  }

  static async json(requestPayload: RequestPayload) {
    try {
      const response = await this._fetch(requestPayload);
      const text = await this.readResponseText(response);
      let json: unknown;
      try {
        json = JSON.parse(text);
      } catch (e) {
        // A 200 that is not JSON is a failure of THIS tool, and the body is the evidence for it.
        throw new FetchFailure(
          "invalid_response",
          `the site answered with something that is not JSON: ${e instanceof Error ? e.message : String(e)}`,
          statusLine(response.status, (response as { statusText?: string }).statusText),
          text,
        );
      }
      let jsonString = JSON.stringify(json);
      
      // Apply length limits
      jsonString = this.applyLengthLimits(
        jsonString,
        requestPayload.max_length ?? downloadLimit,
        requestPayload.start_index ?? 0
      );

      return {
        content: [{ type: "text", text: jsonString }],
        isError: false,
      };
    } catch (error) {
      return resultFor(error, "fetch the JSON");
    }
  }

  static async txt(requestPayload: RequestPayload) {
    try {
      const response = await this._fetch(requestPayload);
      const html = await this.readResponseText(response);

      const dom = new JSDOM(html);
      const document = dom.window.document;

      const scripts = document.getElementsByTagName("script");
      const styles = document.getElementsByTagName("style");
      Array.from(scripts).forEach((script) => script.remove());
      Array.from(styles).forEach((style) => style.remove());

      const text = document.body.textContent || "";
      let normalizedText = text.replace(/\s+/g, " ").trim();
      
      // Apply length limits
      normalizedText = this.applyLengthLimits(
        normalizedText,
        requestPayload.max_length ?? downloadLimit,
        requestPayload.start_index ?? 0
      );

      return {
        content: [{ type: "text", text: normalizedText }],
        isError: false,
      };
    } catch (error) {
      return resultFor(error, "fetch the page as text");
    }
  }

  private static async fetchTranscriptViaYtDlp(
    videoUrl: string,
    lang: string,
  ): Promise<{ xml: string; lang: string; langName: string }> {
    if (!/^[a-zA-Z0-9-]+$/.test(lang)) {
      throw new FetchFailure(
        "bad_request",
        `the language code "${lang}" is not valid. Only letters, digits, and hyphens are allowed.`,
      );
    }
    const { execFileSync, execSync } = await import("child_process");
    const tmpDir = execSync("mktemp -d", { encoding: "utf-8" }).trim();
    try {
      execFileSync(
        "yt-dlp",
        [
          "--write-sub", "--sub-lang", lang,
          "--sub-format", "srv1",
          "--skip-download",
          "-o", `${tmpDir}/sub`,
          videoUrl,
        ],
        { encoding: "utf-8", timeout: 30000, stdio: ["pipe", "pipe", "pipe"] },
      );
      const { readdirSync, readFileSync } = await import("fs");
      const files = readdirSync(tmpDir).filter((f: string) => f.endsWith(".srv1"));
      if (files.length === 0) {
        // Coded so the caller above can tell "yt-dlp found nothing" (fall back to the direct
        // path) from "the request was refused" (do not).
        throw new FetchFailure("no_transcript", "yt-dlp produced no subtitle files.");
      }
      const file = files[0];
      const xml = readFileSync(`${tmpDir}/${file}`, "utf-8");
      const matchedLang = file.match(/\.([^.]+)\.srv1$/)?.[1] ?? lang;
      return { xml, lang: matchedLang, langName: matchedLang };
    } finally {
      const { rmSync } = await import("fs");
      rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  private static async fetchTranscriptDirect(
    requestPayload: YouTubeTranscriptPayload,
  ): Promise<{ xml: string; lang: string; langName: string }> {
    const response = await this._fetch(requestPayload);
    const html = await this.readResponseText(response);

    const playerResponse = YouTubeTranscript.extractPlayerResponse(html);
    const tracks = YouTubeTranscript.getCaptionTracks(playerResponse);

    const lang = requestPayload.lang ?? "en";
    const track =
      tracks.find((t: any) => t.languageCode === lang) ?? tracks[0];
    if (!track || typeof track.baseUrl !== "string") {
      throw new FetchFailure("no_transcript", "the video lists no usable caption track.");
    }

    const captionUrl = track.baseUrl + (track.baseUrl.includes("fmt=") ? "" : "&fmt=srv1");
    const captionResponse = await this._fetch({
      url: captionUrl,
      headers: requestPayload.headers,
      proxy: requestPayload.proxy,
    });

    const xml = await this.readResponseText(captionResponse);
    return {
      xml,
      lang: track.languageCode,
      langName: track.name?.simpleText ?? "Unknown",
    };
  }

  static hasYtDlp: boolean | null = null;

  static async checkYtDlp(): Promise<boolean> {
    if (this.hasYtDlp !== null) return this.hasYtDlp;
    try {
      const { execSync } = await import("child_process");
      execSync("which yt-dlp", { encoding: "utf-8", stdio: "pipe" });
      this.hasYtDlp = true;
    } catch {
      this.hasYtDlp = false;
    }
    return this.hasYtDlp;
  }

  static async youtubeTranscript(requestPayload: YouTubeTranscriptPayload) {
    try {
      const lang = requestPayload.lang ?? "en";
      let result: { xml: string; lang: string; langName: string };

      if (await this.checkYtDlp()) {
        // Validate lang before attempting yt-dlp — this is a security check that must not be swallowed
        if (!/^[a-zA-Z0-9-]+$/.test(lang)) {
          throw new FetchFailure(
            "bad_request",
            `the language code "${lang}" is not valid. Only letters, digits, and hyphens are allowed.`,
          );
        }
        try {
          result = await this.fetchTranscriptViaYtDlp(requestPayload.url, lang);
        } catch (e) {
          // yt-dlp not producing captions is not a failure while the direct path is still open.
          // A blocked or malformed request is, and must not be lost to the fallback.
          if (e instanceof FetchFailure && e.code !== "no_transcript") throw e;
          result = await this.fetchTranscriptDirect(requestPayload);
        }
      } else {
        result = await this.fetchTranscriptDirect(requestPayload);
      }

      const lines = YouTubeTranscript.parseTranscriptXml(result.xml);
      const header = `[Transcript language: ${result.lang} — ${result.langName}]\n\n`;
      let transcript = header + lines.join("\n");

      transcript = this.applyLengthLimits(
        transcript,
        requestPayload.max_length ?? downloadLimit,
        requestPayload.start_index ?? 0,
      );

      return { content: [{ type: "text", text: transcript }], isError: false };
    } catch (error) {
      return resultFor(error, "fetch the transcript");
    }
  }

  static async readable(requestPayload: RequestPayload) {
    try {
      const response = await this._fetch(requestPayload);
      const html = await this.readResponseText(response);

      const dom = new JSDOM(html, { url: requestPayload.url });
      const reader = new Readability(dom.window.document);
      const article = reader.parse();

      if (!article) {
        throw new FetchFailure("unreadable_content", "the page has no article content to read.");
      }

      const turndownService = new TurndownService();
      let content = turndownService.turndown(article.content ?? "");

      content = this.applyLengthLimits(
        content,
        requestPayload.max_length ?? downloadLimit,
        requestPayload.start_index ?? 0
      );

      return { content: [{ type: "text", text: content }], isError: false };
    } catch (error) {
      return resultFor(error, "read the article");
    }
  }

  static async markdown(requestPayload: RequestPayload) {
    try {
      const response = await this._fetch(requestPayload);
      const html = await this.readResponseText(response);
      const turndownService = new TurndownService();
      let markdown = turndownService.turndown(html);
      
      // Apply length limits
      markdown = this.applyLengthLimits(
        markdown,
        requestPayload.max_length ?? downloadLimit,
        requestPayload.start_index ?? 0
      );

      return { content: [{ type: "text", text: markdown }], isError: false };
    } catch (error) {
      return resultFor(error, "fetch the page as Markdown");
    }
  }
}
