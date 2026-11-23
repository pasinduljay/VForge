import { NextRequest, NextResponse } from "next/server";

function resolveKeycloakBaseUrl(): string {
  return (process.env.INTERNAL_KEYCLOAK_BASE_URL || "http://keycloak:8080").replace(/\/+$/, "");
}

function buildKeycloakTargetUrl(
  request: NextRequest,
  prefix: "realms" | "resources",
  segments: string[],
): string | null {
  for (const segment of segments) {
    if (!segment || segment === "." || segment === ".." || segment.includes("\\")) {
      return null;
    }
  }
  const joinedPath = segments.map((seg) => encodeURIComponent(seg)).join("/");
  const search = request.nextUrl.search;
  return `${resolveKeycloakBaseUrl()}/${prefix}/${joinedPath}${search}`;
}

export async function forwardKeycloakRequest(
  request: NextRequest,
  prefix: "realms" | "resources",
  context: { params: Promise<{ path: string[] }> },
): Promise<NextResponse> {
  const { path } = await context.params;
  const targetUrl = buildKeycloakTargetUrl(request, prefix, path);
  if (!targetUrl) {
    return NextResponse.json(
      { error: { code: "validation_error", message: "Invalid IdP path" } },
      { status: 400 },
    );
  }

  const outboundHeaders = new Headers();
  const forwardHeaderNames = [
    "accept",
    "accept-language",
    "authorization",
    "content-type",
    "cookie",
    "origin",
    "referer",
    "user-agent",
    "x-forwarded-for",
  ];
  for (const name of forwardHeaderNames) {
    const val = request.headers.get(name);
    if (val) {
      outboundHeaders.set(name, val);
    }
  }

  const rawHost = request.headers.get("x-forwarded-host") || request.headers.get("host") || "";
  const host = rawHost.split(",")[0].trim();
  const rawProto = request.headers.get("x-forwarded-proto") || "";
  const proto =
    rawProto.split(",")[0].trim() || request.nextUrl.protocol.replace(":", "") || "http";

  if (host) {
    outboundHeaders.set("x-forwarded-host", host);
  }
  outboundHeaders.set("x-forwarded-proto", proto);
  if (proto === "https") {
    outboundHeaders.set("x-forwarded-port", "443");
  } else if (host.includes(":")) {
    outboundHeaders.set("x-forwarded-port", host.split(":")[1]);
  } else {
    outboundHeaders.set("x-forwarded-port", "80");
  }

  const method = request.method.toUpperCase();
  const hasBody = method !== "GET" && method !== "HEAD";
  const body = hasBody ? await request.arrayBuffer() : undefined;

  let upstream: Response;
  try {
    upstream = await fetch(targetUrl, {
      method,
      headers: outboundHeaders,
      body: hasBody ? body : undefined,
      redirect: "manual",
      cache: "no-store",
      signal: AbortSignal.timeout(25_000),
    });
  } catch {
    return NextResponse.json(
      { error: { code: "bad_gateway", message: "Identity provider is unavailable" } },
      { status: 502 },
    );
  }

  const responseHeaders = new Headers();
  const passthroughHeaders = [
    "content-type",
    "content-disposition",
    "content-security-policy",
    "location",
    "etag",
    "last-modified",
  ];
  for (const name of passthroughHeaders) {
    const val = upstream.headers.get(name);
    if (val) {
      responseHeaders.set(name, val);
    }
  }
  responseHeaders.set("cache-control", "no-cache, no-store, must-revalidate");

  const setCookies =
    typeof upstream.headers.getSetCookie === "function" ? upstream.headers.getSetCookie() : [];
  for (const cookieValue of setCookies) {
    responseHeaders.append("set-cookie", cookieValue);
  }
  if (setCookies.length === 0) {
    const fallbackCookie = upstream.headers.get("set-cookie");
    if (fallbackCookie) {
      responseHeaders.append("set-cookie", fallbackCookie);
    }
  }

  const payload =
    upstream.status === 204 || upstream.status === 304 ? null : await upstream.arrayBuffer();

  return new NextResponse(payload, {
    status: upstream.status,
    headers: responseHeaders,
  });
}
