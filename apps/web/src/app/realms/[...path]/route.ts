import { NextRequest } from "next/server";

import { forwardKeycloakRequest } from "@/lib/keycloakProxy";

export const dynamic = "force-dynamic";

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  return forwardKeycloakRequest(request, "realms", context);
}

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  return forwardKeycloakRequest(request, "realms", context);
}

export async function PUT(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  return forwardKeycloakRequest(request, "realms", context);
}

export async function DELETE(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  return forwardKeycloakRequest(request, "realms", context);
}
