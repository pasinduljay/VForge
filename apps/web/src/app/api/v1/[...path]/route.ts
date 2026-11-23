import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

function resolveBackendBaseUrl(): string {
  return (process.env.INTERNAL_API_BASE_URL || "http://api:8000").replace(/\/+$/, "");
}

function buildTargetUrl(request: NextRequest, segments: string[]): string | null {
  for (const segment of segments) {
    if (!segment || segment === "." || segment === ".." || segment.includes("\\")) {
      return null;
    }
  }
  const joinedPath = segments.map((seg) => encodeURIComponent(seg)).join("/");
  const search = request.nextUrl.search;
  return `${resolveBackendBaseUrl()}/api/v1/${joinedPath}${search}`;
}

async function forwardRequest(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
): Promise<NextResponse> {
  const { path } = await context.params;
  const targetUrl = buildTargetUrl(request, path);
  if (!targetUrl) {
    return NextResponse.json(
      { error: { code: "validation_error", message: "Invalid API path" } },
      { status: 400 },
    );
  }

  const outboundHeaders = new Headers();
  const forwardHeaderNames = [
    "accept",
    "authorization",
    "content-type",
    "cookie",
    "idempotency-key",
    "x-csrf-token",
    "x-correlation-id",
    "x-forwarded-for",
  ];
  for (const name of forwardHeaderNames) {
    const val = request.headers.get(name);
    if (val) {
      outboundHeaders.set(name, val);
    }
  }

  const host = request.headers.get("x-forwarded-host") || request.headers.get("host");
  if (host) {
    outboundHeaders.set("x-forwarded-host", host.split(",")[0].trim());
  }
  const forwardedProto = request.headers.get("x-forwarded-proto");
  outboundHeaders.set(
    "x-forwarded-proto",
    forwardedProto
      ? forwardedProto.split(",")[0].trim()
      : request.nextUrl.protocol.replace(":", "") || "http",
  );

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
  } catch (err) {
    if (err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError")) {
      return NextResponse.json(
        { error: { code: "gateway_timeout", message: "Control-plane API request timed out" } },
        { status: 504 },
      );
    }
    return NextResponse.json(
      { error: { code: "bad_gateway", message: "Control-plane API is unavailable" } },
      { status: 502 },
    );
  }

  const responseHeaders = new Headers();
  const passthroughHeaders = [
    "content-type",
    "content-disposition",
    "content-length",
    "location",
    "x-correlation-id",
    "cache-control",
    "retry-after",
  ];
  for (const name of passthroughHeaders) {
    const val = upstream.headers.get(name);
    if (val) {
      responseHeaders.set(name, val);
    }
  }

  const setCookies =
    typeof upstream.headers.getSetCookie === "function"
      ? upstream.headers.getSetCookie()
      : [];
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
    upstream.status === 204 || upstream.status === 304
      ? null
      : await upstream.arrayBuffer();

  return new NextResponse(payload, {
    status: upstream.status,
    headers: responseHeaders,
  });
}

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  return forwardRequest(request, context);
}

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  return forwardRequest(request, context);
}

export async function PATCH(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  return forwardRequest(request, context);
}

export async function PUT(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  return forwardRequest(request, context);
}

export async function DELETE(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  return forwardRequest(request, context);
}
