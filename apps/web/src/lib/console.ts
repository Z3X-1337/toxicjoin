import type { PipelineRequest, PipelineResponse } from "../types";

/**
 * Live console transport.
 *
 * A console that silently answered from canned data would misrepresent a dead backend
 * as a working privacy firewall, so every failure surfaces as an error the operator can see.
 */

const CONSOLE_TIMEOUT_MS = 20_000;

export type ConsoleMode = "analyze" | "execute";

export class ConsoleApiError extends Error {
  public constructor(
    message: string,
    public readonly status?: number,
    public readonly code?: string,
  ) {
    super(message);
    this.name = "ConsoleApiError";
  }
}

interface ApiErrorBody {
  detail?: unknown;
}

function extractErrorCode(body: unknown): string | undefined {
  if (typeof body !== "object" || body === null) {
    return undefined;
  }
  const detail = (body as ApiErrorBody).detail;
  if (typeof detail === "string") {
    return detail;
  }
  if (typeof detail === "object" && detail !== null && "code" in detail) {
    const code = (detail as { code?: unknown }).code;
    return typeof code === "string" ? code : undefined;
  }
  return undefined;
}

function describeStatus(status: number, code?: string): string {
  if (code) {
    switch (code) {
      case "REQUEST_BODY_TOO_LARGE":
        return "The query exceeded the API request budget.";
      case "RESPONSE_SIZE_LIMIT_EXCEEDED":
        return "The response exceeded the configured output budget.";
      case "RATE_LIMIT_EXCEEDED":
        return "Rate limit reached. Wait a moment and retry.";
      case "CONCURRENCY_LIMIT_EXCEEDED":
        return "Too many concurrent requests for this principal.";
      case "PIPELINE_PERSISTENCE_FAILURE":
        return "The pipeline could not persist a receipt for this request.";
      default:
        return `${code} (HTTP ${status})`;
    }
  }
  if (status === 401 || status === 403) {
    return "This deployment requires an API credential the console was not given.";
  }
  if (status === 422) {
    return "The request was rejected by the API schema.";
  }
  return `Request failed with HTTP ${status}.`;
}

export const CONSOLE_ENDPOINTS: Record<ConsoleMode, string> = {
  analyze: "/api/analyze",
  execute: "/api/execute-safe",
};

export async function submitConsoleQuery(
  request: PipelineRequest,
  mode: ConsoleMode,
): Promise<PipelineResponse> {
  const controller = new AbortController();
  // Bare timer globals: this module must also load under a non-DOM test environment.
  const timeout = setTimeout(() => controller.abort(), CONSOLE_TIMEOUT_MS);

  try {
    const response = await fetch(CONSOLE_ENDPOINTS[mode], {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(request),
      signal: controller.signal,
    });

    if (!response.ok) {
      let body: unknown = null;
      try {
        body = await response.json();
      } catch {
        body = null;
      }
      const code = extractErrorCode(body);
      throw new ConsoleApiError(describeStatus(response.status, code), response.status, code);
    }

    return (await response.json()) as PipelineResponse;
  } catch (error) {
    if (error instanceof ConsoleApiError) {
      throw error;
    }
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new ConsoleApiError("The request timed out before the API responded.");
    }
    throw new ConsoleApiError(
      "The ToxicJoin API is unreachable. Start it with `bash run.sh` (or `.\\run.ps1`) and retry.",
    );
  } finally {
    clearTimeout(timeout);
  }
}
