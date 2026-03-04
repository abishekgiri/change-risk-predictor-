import { NextRequest, NextResponse } from "next/server";

import { backendFetch } from "@/lib/backend";

function firstParam(value: string | string[] | null): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value ?? undefined;
}

export async function GET(
  request: NextRequest,
  { params }: { params: { workflowId: string } },
) {
  const workflowId = encodeURIComponent(params.workflowId);

  try {
    const query: Record<string, string> = {};
    const tenantId = firstParam(request.nextUrl.searchParams.getAll("tenant_id"));
    const projectKey = firstParam(request.nextUrl.searchParams.getAll("project_key"));
    if (tenantId) query.tenant_id = tenantId;
    if (projectKey) query.project_key = projectKey;

    const { data } = await backendFetch<Record<string, unknown>>(
      `/integrations/jira/workflows/${workflowId}/transitions`,
      {
        method: "GET",
        query,
      },
    );
    return NextResponse.json(data);
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Request failed" },
      { status: 500 },
    );
  }
}
