import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import fastifyCors from "@fastify/cors";
import got from "got";
import chalk from "chalk";

type StartProxyOptions = {
  port: number;
  proxyUrl: string;
  proxyPartial: string;
  credentials: boolean;
  origin: string;
  rejectUnauthorized: boolean;
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

const applyUpstreamResponse = (
  upstreamResponse: any,
  reply: FastifyReply,
  origin: string,
  proxyUrl: string,
  routePrefix: string
): void => {
  const upstreamHeaders = { ...upstreamResponse.headers };
  const blockedByResponseHeaders = new Set([
    "clear-site-data",
    "content-security-policy",
    "content-security-policy-report-only",
    "cross-origin-embedder-policy",
    "cross-origin-embedder-policy-report-only",
    "cross-origin-opener-policy",
    "cross-origin-opener-policy-report-only",
    "cross-origin-resource-policy",
    "document-policy",
    "nel",
    "origin-agent-cluster",
    "permissions-policy",
    "report-to",
    "x-content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-webkit-csp",
  ]);
  const accessControlAllowOriginHeader =
    upstreamHeaders["access-control-allow-origin"];

  if (
    accessControlAllowOriginHeader &&
    accessControlAllowOriginHeader !== origin
  ) {
    console.log(
      chalk.blue(
        "Override access-control-allow-origin header from proxied URL: " +
          chalk.green(String(accessControlAllowOriginHeader)) +
          "\n"
      )
    );
    upstreamHeaders["access-control-allow-origin"] = origin;
  }

  const locationHeader = upstreamHeaders.location;
  if (typeof locationHeader === "string") {
    upstreamHeaders.location = rewriteLocationHeader(
      locationHeader,
      proxyUrl,
      routePrefix
    );
  }

  reply.raw.statusCode = upstreamResponse.statusCode ?? 502;
  for (const headerName in upstreamHeaders) {
    if (blockedByResponseHeaders.has(headerName.toLowerCase())) {
      continue;
    }

    const headerValue = upstreamHeaders[headerName];
    const normalizedValue = normalizeHeaderValue(
      headerValue as string | string[] | number | undefined
    );
    if (normalizedValue !== undefined) {
      reply.raw.setHeader(headerName, normalizedValue);
    }
  }

  // Avoid reusing cached responses that may still carry blocked headers.
  reply.raw.setHeader(
    "cache-control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );
  reply.raw.setHeader("pragma", "no-cache");
  reply.raw.setHeader("expires", "0");
};

const proxyRequest = (
  request: FastifyRequest,
  reply: FastifyReply,
  upstreamUrl: string,
  origin: string,
  rejectUnauthorized: boolean,
  proxyUrl: string,
  routePrefix: string
): void => {
  reply.hijack();

  const requestHeaders: Record<string, string | string[] | undefined> = {};
  const allowedHeaders = new Set([
    "accept",
    "accept-language",
    "authorization",
    "content-type",
    "cookie",
    "user-agent",
  ]);

  for (const [headerName, headerValue] of Object.entries(request.headers)) {
    const normalizedName = headerName.toLowerCase();
    if (headerValue === undefined) {
      continue;
    }

    if (
      allowedHeaders.has(normalizedName) ||
      (normalizedName.startsWith("x-") &&
        !normalizedName.startsWith("x-forwarded-"))
    ) {
      requestHeaders[normalizedName] = headerValue as string | string[];
    }
  }

  const upstreamRequest = got.stream(upstreamUrl, {
    method: request.method as any,
    headers: requestHeaders,
    throwHttpErrors: false,
    https: {
      rejectUnauthorized,
    },
  });

  upstreamRequest.on("response", (upstreamResponse: any) => {
    applyUpstreamResponse(upstreamResponse, reply, origin, proxyUrl, routePrefix);
  });

  upstreamRequest.on("error", (error: any) => {
    console.error(chalk.red(`Proxy request failed: ${error.message}`));
    if (!reply.raw.headersSent) {
      reply.raw.statusCode = 502;
      reply.raw.setHeader("content-type", "application/json; charset=utf-8");
      reply.raw.end(JSON.stringify({ error: "Proxy request failed" }));
    } else {
      reply.raw.end();
    }
  });

  if (request.method === "GET" || request.method === "HEAD") {
    upstreamRequest.end();
  } else {
    request.raw.pipe(upstreamRequest);
  }
  upstreamRequest.pipe(reply.raw);
};

const startProxy = async ({
  port,
  proxyUrl,
  proxyPartial,
  credentials,
  origin,
  rejectUnauthorized,
}: StartProxyOptions): Promise<void> => {
  const cleanProxyUrl = proxyUrl.replace(/\/$/, "");
  const cleanProxyPartial = proxyPartial.replace(/^\/+|\/+$/g, "");
  const useRootProxy = cleanProxyPartial.length === 0;
  const routePrefix = useRootProxy ? "" : `/${cleanProxyPartial}`;
  const proxy = Fastify();

  await proxy.register(fastifyCors, { credentials, origin });

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
          origin,
          rejectUnauthorized,
          cleanProxyUrl,
          routePrefix
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
          origin,
          rejectUnauthorized,
          cleanProxyUrl,
          routePrefix
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
          origin,
          rejectUnauthorized,
          cleanProxyUrl,
          routePrefix
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
          origin,
          rejectUnauthorized,
          cleanProxyUrl,
          routePrefix
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
};

export { startProxy };
export type { StartProxyOptions };
