import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({
    status: "ok",
    service: "vforge-web",
    phase: 15,
    timestamp: new Date().toISOString(),
  });
}
