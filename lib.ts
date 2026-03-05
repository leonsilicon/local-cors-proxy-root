import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import got from "got";
import chalk from "chalk";

type StartProxyOptions = {
  port: number;
  proxyUrl: string;
  proxyPartial: string;
  credentials: boolean;
  origin: string;
  rejectUnauthorized: boolean;
  debug: boolean;
  browserHeaders: boolean;
};

const PROXY_METHODS: Array<"DELETE" | "GET" | "HEAD" | "PATCH" | "POST" | "PUT"> = [
  "DELETE",
  "GET",
  "HEAD",
  "PATCH",
  "POST",
  "PUT",
];

const normalizeHeaderValue = (
  value: string | string[] | number | undefined
): string | string[] | undefined => {
  if (value === undefined) {
    return undefined;
  }

  if (Array.isArray(value)) {
    return value;
  }

  return String(value);
};

const shouldStripResponseHeader = (headerName: string): boolean => {
  const normalized = headerName.toLowerCase();

  if (normalized.startsWith("access-control-")) {
    return true;
  }

  const blockedByName = new Set([
    "accept-ch",
    "accept-ch-lifetime",
    "alt-svc",
    "clear-site-data",
    "content-disposition",
    "content-security-policy",
    "content-security-policy-report-only",
    "cross-origin-embedder-policy",
    "cross-origin-embedder-policy-report-only",
    "cross-origin-opener-policy",
    "cross-origin-opener-policy-report-only",
    "cross-origin-resource-policy",
    "document-policy",
    "expect-ct",
    "nel",
    "origin-agent-cluster",
    "permissions-policy",
    "referrer-policy",
    "report-to",
    "strict-transport-security",
    "x-content-security-policy",
    "x-content-type-options",
    "x-download-options",
    "x-frame-options",
    "x-permitted-cross-domain-policies",
    "x-webkit-csp",
  ]);

  return blockedByName.has(normalized);
};

const getDebugTimestamp = (): string => new Date().toISOString();

const sanitizeHeadersForLog = (
  headers: Record<string, string | string[] | number | undefined>
): Record<string, string | string[] | number | undefined> => {
  const redactedHeaders = new Set(["authorization", "cookie", "set-cookie"]);
  const sanitized: Record<string, string | string[] | number | undefined> = {};

  for (const [headerName, headerValue] of Object.entries(headers)) {
    const normalizedName = headerName.toLowerCase();
    sanitized[headerName] = redactedHeaders.has(normalizedName)
      ? "[REDACTED]"
      : headerValue;
  }

  return sanitized;
};

const logDebug = (
  debugEnabled: boolean,
  event: string,
  details: Record<string, unknown>
): void => {
  if (!debugEnabled) {
    return;
  }

  const payload = {
    ts: getDebugTimestamp(),
    event,
    ...details,
  };

  console.log(`[lcp-debug] ${JSON.stringify(payload)}`);
};

const buildRequestHeaders = (
  incomingHeaders: FastifyRequest["headers"],
  method: string,
  browserHeaders: boolean
): Record<string, string | string[] | undefined> => {
  const requestHeaders: Record<string, string | string[] | undefined> = {};
  const blockedRequestHeaders = new Set([
    "connection",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
  ]);

  for (const [headerName, headerValue] of Object.entries(incomingHeaders)) {
    const normalizedName = headerName.toLowerCase();
    if (headerValue === undefined || blockedRequestHeaders.has(normalizedName)) {
      continue;
    }

    requestHeaders[normalizedName] = headerValue as string | string[];
  }

  if (!browserHeaders) {
    return requestHeaders;
  }

  if (!requestHeaders["user-agent"]) {
    requestHeaders["user-agent"] =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
      "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
  }
  if (!requestHeaders.accept) {
    requestHeaders.accept =
      "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp," +
      "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
  }
  if (!requestHeaders["accept-language"]) {
    requestHeaders["accept-language"] = "en-US,en;q=0.9";
  }
  if (!requestHeaders["accept-encoding"]) {
    requestHeaders["accept-encoding"] = "gzip, deflate, br";
  }

  if (method === "GET") {
    if (!requestHeaders["upgrade-insecure-requests"]) {
      requestHeaders["upgrade-insecure-requests"] = "1";
    }
    if (!requestHeaders["sec-fetch-mode"]) {
      requestHeaders["sec-fetch-mode"] = "navigate";
    }
    if (!requestHeaders["sec-fetch-dest"]) {
      requestHeaders["sec-fetch-dest"] = "document";
    }
    if (!requestHeaders["sec-fetch-site"]) {
      requestHeaders["sec-fetch-site"] = "none";
    }
    if (!requestHeaders["sec-fetch-user"]) {
      requestHeaders["sec-fetch-user"] = "?1";
    }
  }

  return requestHeaders;
};

const rewriteLocationHeader = (
  locationHeader: string,
  proxyUrl: string,
  routePrefix: string
): string => {
  const trimmedLocation = locationHeader.trim();
  const normalizedRoutePrefix = routePrefix === "" ? "" : routePrefix;

  if (trimmedLocation.startsWith("/")) {
    return normalizedRoutePrefix
      ? `${normalizedRoutePrefix}${trimmedLocation}`
      : trimmedLocation;
  }

  if (trimmedLocation.startsWith("//")) {
    try {
      const parsedProxyUrl = new URL(proxyUrl);
      const protocolRelative = `${parsedProxyUrl.protocol}${trimmedLocation}`;
      const parsedLocation = new URL(protocolRelative);
      if (parsedLocation.origin === parsedProxyUrl.origin) {
        return normalizedRoutePrefix
          ? `${normalizedRoutePrefix}${parsedLocation.pathname}${parsedLocation.search}${parsedLocation.hash}`
          : `${parsedLocation.pathname}${parsedLocation.search}${parsedLocation.hash}`;
      }
    } catch {
      return locationHeader;
    }
  }

  try {
    const parsedProxyUrl = new URL(proxyUrl);
    const parsedLocation = new URL(trimmedLocation);
    if (parsedLocation.origin !== parsedProxyUrl.origin) {
      return locationHeader;
    }

    return normalizedRoutePrefix
      ? `${normalizedRoutePrefix}${parsedLocation.pathname}${parsedLocation.search}${parsedLocation.hash}`
      : `${parsedLocation.pathname}${parsedLocation.search}${parsedLocation.hash}`;
  } catch {
    return locationHeader;
  }
};

const buildProxyPublicBaseUrl = (
  request: FastifyRequest,
  routePrefix: string
): string => {
  const host = String(request.headers.host ?? "localhost");
  const forwardedProto = request.headers["x-forwarded-proto"];
  const protocol = typeof forwardedProto === "string" ? forwardedProto : "http";
  return `${protocol}://${host}${routePrefix}`;
};

const shouldRewriteBody = (method: string, contentTypeHeader: unknown): boolean => {
  if (method !== "GET") {
    return false;
  }

  const contentType = String(contentTypeHeader ?? "");
  return /text\/html|application\/javascript|text\/javascript|application\/json/i.test(
    contentType
  );
};

const replaceAllOccurrences = (
  source: string,
  searchValue: string,
  replaceValue: string
): { text: string; count: number } => {
  if (!searchValue || searchValue === replaceValue) {
    return { text: source, count: 0 };
  }

  const escapedSearch = searchValue.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(escapedSearch, "g");
  const matches = source.match(pattern);
  const count = matches ? matches.length : 0;
  if (count === 0) {
    return { text: source, count: 0 };
  }
  return { text: source.replace(pattern, replaceValue), count };
};

const rewriteResponseBodyText = (
  originalText: string,
  proxyUrl: string,
  proxyPublicBaseUrl: string
): { text: string; replacementCount: number } => {
  const parsedProxyUrl = new URL(proxyUrl);
  const candidates = new Set<string>();
  const hostname = parsedProxyUrl.hostname;
  const withWww = hostname.startsWith("www.") ? hostname : `www.${hostname}`;
  const withoutWww = hostname.startsWith("www.") ? hostname.slice(4) : hostname;

  candidates.add(`${parsedProxyUrl.protocol}//${withWww}`);
  candidates.add(`${parsedProxyUrl.protocol}//${withoutWww}`);

  let rewrittenText = originalText;
  let replacementCount = 0;

  for (const sourceOrigin of candidates) {
    const plain = replaceAllOccurrences(rewrittenText, sourceOrigin, proxyPublicBaseUrl);
    rewrittenText = plain.text;
    replacementCount += plain.count;

    const slashEscapedSource = sourceOrigin.replace(/\//g, "\\/");
    const slashEscapedProxy = proxyPublicBaseUrl.replace(/\//g, "\\/");
    const slashEscaped = replaceAllOccurrences(
      rewrittenText,
      slashEscapedSource,
      slashEscapedProxy
    );
    rewrittenText = slashEscaped.text;
    replacementCount += slashEscaped.count;

    const encodedSource = encodeURIComponent(sourceOrigin);
    const encodedProxy = encodeURIComponent(proxyPublicBaseUrl);
    const encoded = replaceAllOccurrences(rewrittenText, encodedSource, encodedProxy);
    rewrittenText = encoded.text;
    replacementCount += encoded.count;
  }

  return { text: rewrittenText, replacementCount };
};

const applyUpstreamResponse = (
  upstreamResponse: any,
  reply: FastifyReply,
  proxyUrl: string,
  routePrefix: string,
  debug: boolean,
  requestId: string
): void => {
  const upstreamHeaders = { ...upstreamResponse.headers };
  const strippedHeaders: string[] = [];
  const forwardedHeaders: string[] = [];

  const locationHeader = upstreamHeaders.location;
  if (typeof locationHeader === "string") {
    const rewrittenLocation = rewriteLocationHeader(
      locationHeader,
      proxyUrl,
      routePrefix
    );
    upstreamHeaders.location = rewrittenLocation;
    if (rewrittenLocation !== locationHeader) {
      logDebug(debug, "response.location_rewritten", {
        requestId,
        before: locationHeader,
        after: rewrittenLocation,
      });
    }
  }

  reply.raw.statusCode = upstreamResponse.statusCode ?? 502;
  for (const headerName in upstreamHeaders) {
    if (shouldStripResponseHeader(headerName)) {
      strippedHeaders.push(headerName);
      continue;
    }

    const headerValue = upstreamHeaders[headerName];
    const normalizedValue = normalizeHeaderValue(
      headerValue as string | string[] | number | undefined
    );
    if (normalizedValue !== undefined) {
      reply.raw.setHeader(headerName, normalizedValue);
      forwardedHeaders.push(headerName);
    }
  }

  // Avoid reusing cached responses that may still carry blocked headers.
  reply.raw.setHeader(
    "cache-control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );
  reply.raw.setHeader("pragma", "no-cache");
  reply.raw.setHeader("expires", "0");

  logDebug(debug, "response.upstream", {
    requestId,
    statusCode: upstreamResponse.statusCode ?? 502,
    strippedHeaders,
    forwardedHeaders,
    upstreamHeaders: sanitizeHeadersForLog(
      upstreamHeaders as Record<string, string | string[] | number | undefined>
    ),
  });
};

const proxyRequest = (
  request: FastifyRequest,
  reply: FastifyReply,
  upstreamUrl: string,
  rejectUnauthorized: boolean,
  proxyUrl: string,
  routePrefix: string,
  debug: boolean,
  browserHeaders: boolean
): void => {
  reply.hijack();
  const requestId = `${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
  const startedAt = Date.now();
  const proxyPublicBaseUrl = buildProxyPublicBaseUrl(request, routePrefix);

  const requestHeaders = buildRequestHeaders(
    request.headers,
    request.method,
    browserHeaders
  );

  logDebug(debug, "request.received", {
    requestId,
    method: request.method,
    incomingUrl: request.raw.url ?? "/",
    upstreamUrl,
    proxyPublicBaseUrl,
    incomingHeaders: sanitizeHeadersForLog(
      request.headers as Record<string, string | string[] | number | undefined>
    ),
    forwardedHeaders: sanitizeHeadersForLog(requestHeaders),
  });
  logDebug(debug, "upstream.request_start", {
    requestId,
    method: request.method,
    upstreamUrl,
    rejectUnauthorized,
    browserHeaders,
  });

  const upstreamRequest = got.stream(upstreamUrl, {
    method: request.method as any,
    headers: requestHeaders,
    decompress: true,
    throwHttpErrors: false,
    https: {
      rejectUnauthorized,
    },
  });
  upstreamRequest.on("redirect", (response: any, nextOptions: any) => {
    logDebug(debug, "upstream.redirect", {
      requestId,
      statusCode: response?.statusCode ?? null,
      location: response?.headers?.location ?? null,
      nextUrl: nextOptions?.url?.toString?.() ?? String(nextOptions?.url ?? ""),
    });
  });

  upstreamRequest.on("response", (upstreamResponse: any) => {
    let upstreamBytes = 0;
    let upstreamChunks = 0;

    applyUpstreamResponse(
      upstreamResponse,
      reply,
      proxyUrl,
      routePrefix,
      debug,
      requestId
    );

    const rewriteBody = shouldRewriteBody(
      request.method,
      upstreamResponse.headers["content-type"]
    );
    logDebug(debug, "response.rewrite_decision", {
      requestId,
      method: request.method,
      contentType: String(upstreamResponse.headers["content-type"] ?? ""),
      rewriteBody,
    });
    upstreamResponse.on("aborted", () => {
      logDebug(debug, "upstream.response_aborted", {
        requestId,
        receivedBytes: upstreamBytes,
        receivedChunks: upstreamChunks,
      });
    });
    upstreamResponse.on("close", () => {
      logDebug(debug, "upstream.response_close", {
        requestId,
        receivedBytes: upstreamBytes,
        receivedChunks: upstreamChunks,
      });
    });
    upstreamResponse.on("error", (error: any) => {
      logDebug(debug, "response.stream_error", {
        requestId,
        message: error?.message ?? "Unknown upstream stream error",
      });
      if (!reply.raw.headersSent) {
        reply.raw.statusCode = 502;
      }
      reply.raw.end();
    });

    if (!rewriteBody) {
      upstreamResponse.on("data", (chunk: Buffer | string) => {
        const size = Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(chunk);
        upstreamBytes += size;
        upstreamChunks += 1;
      });
      upstreamResponse.on("end", () => {
        logDebug(debug, "upstream.response_end", {
          requestId,
          receivedBytes: upstreamBytes,
          receivedChunks: upstreamChunks,
        });
      });
      upstreamResponse.pipe(reply.raw);
      logDebug(debug, "response.pass_through_stream", {
        requestId,
      });
      return;
    }

    const chunks: Buffer[] = [];
    upstreamResponse.on("data", (chunk: Buffer | string) => {
      const normalizedChunk = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      chunks.push(normalizedChunk);
      upstreamBytes += normalizedChunk.length;
      upstreamChunks += 1;
    });
    upstreamResponse.on("end", () => {
      logDebug(debug, "upstream.response_end", {
        requestId,
        receivedBytes: upstreamBytes,
        receivedChunks: upstreamChunks,
      });
      try {
        const originalBody = Buffer.concat(chunks).toString("utf8");
        const rewritten = rewriteResponseBodyText(
          originalBody,
          proxyUrl,
          proxyPublicBaseUrl
        );

        reply.raw.removeHeader("content-length");
        reply.raw.removeHeader("transfer-encoding");
        reply.raw.setHeader("content-length", Buffer.byteLength(rewritten.text, "utf8"));

        logDebug(debug, "response.body_rewritten", {
          requestId,
          contentType: upstreamResponse.headers["content-type"] ?? "",
          originalBytes: Buffer.byteLength(originalBody, "utf8"),
          rewrittenBytes: Buffer.byteLength(rewritten.text, "utf8"),
          chunkCount: chunks.length,
          replacementCount: rewritten.replacementCount,
        });

        reply.raw.end(rewritten.text);
      } catch (error: any) {
        const originalBody = Buffer.concat(chunks).toString("utf8");
        reply.raw.removeHeader("content-length");
        reply.raw.removeHeader("transfer-encoding");
        reply.raw.setHeader("content-length", Buffer.byteLength(originalBody, "utf8"));
        logDebug(debug, "response.body_rewrite_error", {
          requestId,
          contentType: upstreamResponse.headers["content-type"] ?? "",
          originalBytes: Buffer.byteLength(originalBody, "utf8"),
          chunkCount: chunks.length,
          message: error?.message ?? "Unknown body rewrite error",
        });
        reply.raw.end(originalBody);
      }
    });
  });

  upstreamRequest.on("error", (error: any) => {
    logDebug(debug, "request.error", {
      requestId,
      elapsedMs: Date.now() - startedAt,
      message: error?.message ?? "Unknown proxy error",
      name: error?.name ?? "Error",
      code: error?.code ?? null,
    });
    console.error(chalk.red(`Proxy request failed: ${error.message}`));
    if (!reply.raw.headersSent) {
      reply.raw.statusCode = 502;
      reply.raw.setHeader("content-type", "application/json; charset=utf-8");
      reply.raw.end(JSON.stringify({ error: "Proxy request failed" }));
    } else {
      reply.raw.end();
    }
  });
  upstreamRequest.on("close", () => {
    logDebug(debug, "upstream.request_close", {
      requestId,
      elapsedMs: Date.now() - startedAt,
    });
  });

  if (request.method === "GET" || request.method === "HEAD") {
    upstreamRequest.end();
  } else {
    request.raw.pipe(upstreamRequest);
  }
  request.raw.on("aborted", () => {
    logDebug(debug, "client.request_aborted", {
      requestId,
      elapsedMs: Date.now() - startedAt,
    });
  });
  request.raw.on("close", () => {
    logDebug(debug, "client.request_close", {
      requestId,
      elapsedMs: Date.now() - startedAt,
    });
  });
  reply.raw.on("close", () => {
    logDebug(debug, "client.response_close", {
      requestId,
      elapsedMs: Date.now() - startedAt,
      writableEnded: reply.raw.writableEnded,
      headersSent: reply.raw.headersSent,
    });
  });
  reply.raw.on("error", (error: any) => {
    logDebug(debug, "client.response_error", {
      requestId,
      elapsedMs: Date.now() - startedAt,
      message: error?.message ?? "Unknown response socket error",
    });
  });
  reply.raw.on("finish", () => {
    logDebug(debug, "request.finished", {
      requestId,
      elapsedMs: Date.now() - startedAt,
      finalStatusCode: reply.raw.statusCode,
      finalHeaders: sanitizeHeadersForLog(
        reply.raw.getHeaders() as Record<string, string | string[] | number | undefined>
      ),
    });
  });
};

const startProxy = async ({
  port,
  proxyUrl,
  proxyPartial,
  credentials,
  origin,
  rejectUnauthorized,
  debug,
  browserHeaders,
}: StartProxyOptions): Promise<void> => {
  const cleanProxyUrl = proxyUrl.replace(/\/$/, "");
  const cleanProxyPartial = proxyPartial.replace(/^\/+|\/+$/g, "");
  const useRootProxy = cleanProxyPartial.length === 0;
  const routePrefix = useRootProxy ? "" : `/${cleanProxyPartial}`;
  const proxy = Fastify();

  if (useRootProxy) {
    proxy.route({
      method: PROXY_METHODS,
      url: "/*",
      handler: async (request: FastifyRequest, reply: FastifyReply) => {
        const proxiedPath = request.raw.url ?? "/";
        try {
          console.log(chalk.green(`Request Proxied -> ${proxiedPath}`));
        } catch {
          // ignore logging errors
        }

        proxyRequest(
          request,
          reply,
          `${cleanProxyUrl}${proxiedPath}`,
          rejectUnauthorized,
          cleanProxyUrl,
          routePrefix,
          debug,
          browserHeaders
        );
      },
    });

    proxy.route({
      method: PROXY_METHODS,
      url: "/",
      handler: async (request: FastifyRequest, reply: FastifyReply) => {
        try {
          console.log(chalk.green("Request Proxied -> /"));
        } catch {
          // ignore logging errors
        }

        proxyRequest(
          request,
          reply,
          `${cleanProxyUrl}/`,
          rejectUnauthorized,
          cleanProxyUrl,
          routePrefix,
          debug,
          browserHeaders
        );
      },
    });
  } else {
    proxy.route({
      method: PROXY_METHODS,
      url: `${routePrefix}/*`,
      handler: async (request: FastifyRequest, reply: FastifyReply) => {
        const requestUrl = request.raw.url ?? "/";
        const proxiedPath = requestUrl.startsWith(routePrefix)
          ? requestUrl.slice(routePrefix.length) || "/"
          : requestUrl;

        try {
          console.log(chalk.green(`Request Proxied -> ${proxiedPath}`));
        } catch {
          // ignore logging errors
        }

        proxyRequest(
          request,
          reply,
          `${cleanProxyUrl}${proxiedPath}`,
          rejectUnauthorized,
          cleanProxyUrl,
          routePrefix,
          debug,
          browserHeaders
        );
      },
    });

    proxy.route({
      method: PROXY_METHODS,
      url: routePrefix,
      handler: async (request: FastifyRequest, reply: FastifyReply) => {
        try {
          console.log(chalk.green("Request Proxied -> /"));
        } catch {
          // ignore logging errors
        }

        proxyRequest(
          request,
          reply,
          `${cleanProxyUrl}/`,
          rejectUnauthorized,
          cleanProxyUrl,
          routePrefix,
          debug,
          browserHeaders
        );
      },
    });

    proxy.get("/", async (_request: FastifyRequest, reply: FastifyReply) => {
      reply.status(200).send({
        message: "Local CORS proxy is running",
        usage: `Use http://localhost:${port}${routePrefix}/* to proxy requests`,
        proxyUrl: cleanProxyUrl,
      });
    });
  }

  await proxy.listen({ port });

  console.log(chalk.bgGreen.black.bold.underline("\n Proxy Active \n"));
  console.log(chalk.blue("Proxy Url: " + chalk.green(cleanProxyUrl)));
  console.log(
    chalk.blue("Proxy Partial: " + chalk.green(useRootProxy ? "/" : cleanProxyPartial))
  );
  console.log(chalk.blue("PORT: " + chalk.green(String(port))));
  console.log(chalk.blue("Credentials: " + chalk.green(String(credentials))));
  console.log(chalk.blue("Origin: " + chalk.green(origin)));
  console.log(chalk.blue("Debug: " + chalk.green(debug ? "On" : "Off")));
  console.log(
    chalk.blue("Browser Headers: " + chalk.green(browserHeaders ? "On" : "Off"))
  );
  console.log(
    chalk.blue(
      "Reject Unauthorized: " +
        chalk.green(rejectUnauthorized ? "Yes" : "No") +
        "\n"
    )
  );
  console.log(
    chalk.cyan(
      "To start using the proxy simply replace the proxied part of your url with: " +
        chalk.bold(
          useRootProxy
            ? `http://localhost:${port}/\n`
            : `http://localhost:${port}/${cleanProxyPartial}\n`
        )
    )
  );
  logDebug(debug, "proxy.start", {
    port,
    proxyUrl: cleanProxyUrl,
    proxyPartial: useRootProxy ? "/" : cleanProxyPartial,
    credentials,
    origin,
    rejectUnauthorized,
    browserHeaders,
  });
};

export { startProxy };
export type { StartProxyOptions };
