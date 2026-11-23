import { NextRequest } from "next/server";

import { forwardKeycloakRequest } from "@/lib/keycloakProxy";

export const dynamic = "force-dynamic";

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  return forwardKeycloakRequest(request, "resources", context);
}
