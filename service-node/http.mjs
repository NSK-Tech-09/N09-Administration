import { randomUUID } from "node:crypto";
import { evaluateAccessRequestAsync } from "./api.mjs";

const DEFAULT_MAX_BODY_BYTES = 64 * 1024;

class HttpInputError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

function writeJson(response, status, body, correlationId = null) {
  const payload = JSON.stringify(body);
  response.statusCode = status;
  response.setHeader("cache-control", "no-store");
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("x-content-type-options", "nosniff");
  if (correlationId) response.setHeader("x-correlation-id", correlationId);
  response.end(payload);
}

async function readJson(request, maxBodyBytes) {
  const contentType = request.headers["content-type"] ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    throw new HttpInputError(415, "unsupported_media_type");
  }

  const chunks = [];
  let received = 0;
  for await (const chunk of request) {
    received += chunk.length;
    if (received > maxBodyBytes) throw new HttpInputError(413, "request_too_large");
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpInputError(400, "invalid_json");
  }
}

export function createHttpHandler({ repository, authenticate = async () => null, maxBodyBytes = DEFAULT_MAX_BODY_BYTES }) {
  if (!repository) throw new Error("repository is required");
  if (typeof authenticate !== "function") throw new Error("authenticate must be a function");

  return async function handle(request, response) {
    if (request.url === "/health" && request.method === "GET") {
      writeJson(response, 200, { status: "ok" });
      return;
    }
    if (request.url !== "/internal/v1/access-decisions") {
      writeJson(response, 404, { error: "resource_not_found" });
      return;
    }
    if (request.method !== "POST") {
      response.setHeader("allow", "POST");
      writeJson(response, 405, { error: "method_not_allowed" });
      return;
    }

    let correlationId = randomUUID();
    try {
      const payload = await readJson(request, maxBodyBytes);
      const principal = await authenticate(request);
      correlationId = principal?.correlationId || correlationId;
      const result = await evaluateAccessRequestAsync({ repository, principal, payload });
      writeJson(response, result.status, result.body, result.correlationId);
    } catch (error) {
      if (error instanceof HttpInputError) {
        writeJson(response, error.status, { error: error.code }, correlationId);
        return;
      }
      writeJson(response, 500, { error: "internal_error" }, correlationId);
    }
  };
}
