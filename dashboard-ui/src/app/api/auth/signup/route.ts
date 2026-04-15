import { backendFetch } from "@/lib/backend";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const result = await backendFetch<{
      user_id: string;
      tenant_id: string;
      token: string;
      roles: string[];
      redirect_url: string;
    }>("/auth/signup", {
      method: "POST",
      body: JSON.stringify(body),
    });
    return NextResponse.json(result.data);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Signup failed";
    const status = message.includes("400") ? 400 : 500;
    return NextResponse.json({ error: message }, { status });
  }
}
