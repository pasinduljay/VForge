import assert from "node:assert/strict";
import test from "node:test";
import { ApiError } from "../src/lib/api";
import { classifyOrganizationsError } from "../src/lib/organizations-state";

test("classifies 401 as unauthenticated", () => {
  const err = new ApiError(401, "unauthorized", "Authentication required");
  const result = classifyOrganizationsError(err);
  assert.equal(result.kind, "unauthenticated");
  assert.equal(result.status, 401);
  assert.equal(result.title, "Authentication Required");
});

test("classifies 403 as forbidden", () => {
  const err = new ApiError(403, "forbidden", "Insufficient permissions");
  const result = classifyOrganizationsError(err);
  assert.equal(result.kind, "forbidden");
  assert.equal(result.status, 403);
  assert.equal(result.title, "Permission Denied");
  assert.equal(result.message, "Insufficient permissions");
});

test("classifies 502/503/504 as api_unavailable", () => {
  for (const status of [502, 503, 504]) {
    const err = new ApiError(status, "gateway_error", "Service unavailable");
    const result = classifyOrganizationsError(err);
    assert.equal(result.kind, "api_unavailable");
    assert.equal(result.status, status);
    assert.equal(result.title, "Control-Plane API Unavailable");
  }
});

test("classifies network TypeError and TimeoutError as api_unavailable", () => {
  const netResult = classifyOrganizationsError(new TypeError("Failed to fetch"));
  assert.equal(netResult.kind, "api_unavailable");
  assert.equal(netResult.status, null);

  const timeoutErr = new Error("signal timed out");
  timeoutErr.name = "TimeoutError";
  const timeoutResult = classifyOrganizationsError(timeoutErr);
  assert.equal(timeoutResult.kind, "api_unavailable");
  assert.match(timeoutResult.message, /timed out/i);
});

test("classifies unexpected HTTP 500 and unknown values as error", () => {
  const serverResult = classifyOrganizationsError(
    new ApiError(500, "internal_error", "Database query failed"),
  );
  assert.equal(serverResult.kind, "error");
  assert.equal(serverResult.status, 500);
  assert.equal(serverResult.title, "Unable to Load Organizations");

  const unknownResult = classifyOrganizationsError("unexpected");
  assert.equal(unknownResult.kind, "error");
  assert.equal(unknownResult.status, null);
});
