import { Container } from "@cloudflare/containers";

interface Env {
  MCP_SCANNER: DurableObjectNamespace<McpScannerContainer>;
  MCP_SCANNER_API_TOKEN: string;
}

const SCAN_PATH = "/v1/scans/mcp";
const HEALTH_PATH = "/health";

export class McpScannerContainer extends Container<Env> {
  defaultPort = 8787;
  sleepAfter = "10m";
  envVars = {
    IDE_SCANNER_ALLOW_INSECURE_BIND: "1",
    IDE_SCANNER_DATA_DIR: "/data",
  };
}

function isAuthorized(request: Request, env: Env): boolean {
  const token = env.MCP_SCANNER_API_TOKEN;
  if (!token) return false;
  return request.headers.get("authorization") === `Bearer ${token}`;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const validPath =
      url.pathname === HEALTH_PATH ||
      (url.pathname === SCAN_PATH && request.method === "POST");

    if (!validPath) return new Response("Not found", { status: 404 });
    if (!isAuthorized(request, env)) {
      return new Response("Unauthorized", { status: 401 });
    }

    const container = env.MCP_SCANNER.getByName("mcp-scanner");
    return container.fetch(request);
  },
} satisfies ExportedHandler<Env>;
