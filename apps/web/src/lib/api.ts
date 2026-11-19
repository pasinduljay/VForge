"use client";

export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function getCsrfTokenFromCookie(): string | null {
  if (typeof document === "undefined") {
    return null;
  }
  const match = document.cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith("vf_csrf="));
  if (!match) {
    return null;
  }
  return decodeURIComponent(match.slice("vf_csrf=".length));
}

export async function apiFetch<T>(
  path: string,
  options: RequestInit & { csrfToken?: string | null } = {},
): Promise<T> {
  const { csrfToken, headers: customHeaders, method = "GET", ...rest } = options;
  const normalizedMethod = method.toUpperCase();
  const headers = new Headers(customHeaders);

  if (rest.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  if (!["GET", "HEAD", "OPTIONS"].includes(normalizedMethod)) {
    const token = getCsrfTokenFromCookie() ?? csrfToken;
    if (token) {
      headers.set("X-CSRF-Token", token);
    }
  }

  const response = await fetch(path, {
    ...rest,
    method: normalizedMethod,
    headers,
    credentials: "include",
    cache: "no-store",
  });

  if (response.status === 204) {
    return undefined as T;
  }

  let data: unknown = null;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    data = await response.json().catch(() => null);
  } else {
    data = await response.text().catch(() => null);
  }

  if (!response.ok) {
    const errObj =
      typeof data === "object" && data !== null && "error" in data
        ? (data as { error?: { code?: string; message?: string } }).error
        : undefined;
    const message =
      errObj?.message ||
      (typeof data === "object" && data !== null && "detail" in data
        ? String((data as { detail: unknown }).detail)
        : `Request failed with HTTP ${response.status}`);
    throw new ApiError(response.status, errObj?.code || "http_error", message);
  }

  return data as T;
}

export function formatUtc(iso: string | null | undefined): string {
  if (!iso) {
    return "—";
  }
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  return date.toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

export async function signOutAndRedirect(options: {
  csrfToken?: string | null;
  onLocalRedirect?: () => void;
} = {}): Promise<{ navigated: boolean }> {
  const { csrfToken, onLocalRedirect } = options;
  try {
    const res = await apiFetch<{ status: string; logout_url?: string | null }>(
      "/api/v1/auth/logout",
      {
        method: "POST",
        csrfToken,
      },
    );
    if (res?.logout_url) {
      window.location.assign(res.logout_url);
      return { navigated: true };
    }
    onLocalRedirect?.();
    return { navigated: Boolean(onLocalRedirect) };
  } catch (err) {
    if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
      onLocalRedirect?.();
      return { navigated: Boolean(onLocalRedirect) };
    }
    throw err;
  }
}
