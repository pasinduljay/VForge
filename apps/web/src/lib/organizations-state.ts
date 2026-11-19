import { ApiError } from "./api";

export type OrganizationsFailureKind =
  | "unauthenticated"
  | "forbidden"
  | "api_unavailable"
  | "error";

export interface OrganizationsFailure {
  kind: OrganizationsFailureKind;
  status: number | null;
  title: string;
  message: string;
}

export function classifyOrganizationsError(err: unknown): OrganizationsFailure {
  const status = err instanceof ApiError ? err.status : null;
  const rawMessage =
    err instanceof Error && err.message.trim()
      ? err.message
      : "Failed to load organizations.";

  if (status === 401) {
    return {
      kind: "unauthenticated",
      status,
      title: "Authentication Required",
      message: "Sign in to view and manage organizations in VForge.",
    };
  }

  if (status === 403) {
    return {
      kind: "forbidden",
      status,
      title: "Permission Denied",
      message: rawMessage,
    };
  }

  const isTimeoutOrNetwork =
    err instanceof TypeError ||
    (err instanceof Error &&
      (err.name === "TimeoutError" || err.name === "AbortError"));

  if (
    status === 502 ||
    status === 503 ||
    status === 504 ||
    isTimeoutOrNetwork
  ) {
    return {
      kind: "api_unavailable",
      status,
      title: "Control-Plane API Unavailable",
      message:
        err instanceof Error && err.name === "TimeoutError"
          ? "The control-plane API request timed out. Verify backend services are running and retry."
          : rawMessage,
    };
  }

  return {
    kind: "error",
    status,
    title: "Unable to Load Organizations",
    message: rawMessage,
  };
}
