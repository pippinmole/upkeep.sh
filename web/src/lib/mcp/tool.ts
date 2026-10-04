import type { CallToolResult, McpServer } from "@modelcontextprotocol/server";
import * as z from "zod";

import type { McpViewer } from "@/lib/viewer";

import { logMcpCall, type McpCallLogger } from "./log";
import { mcpRateLimiter, type RateLimiter } from "./rate-limit";

// MCP tools (docs/MCP.md#tools). Each tool declares zod input and output
// schemas, runs one read for the viewer's workspace, and returns the result
// twice: as structured content matching the output schema, and as a short
// text rendering for clients that ignore structured content. Every call is
// logged to mcp_calls; errors come back as tool errors (isError), never as
// a failed HTTP request.

// An error whose message is meant for the user (not found, ambiguous,
// temporary password): returned as is. Anything else is logged and
// reported as an internal error without details.
export class ToolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ToolError";
  }
}

export type ToolContext = {
  viewer: McpViewer;
  // Absolute dashboard link for a path ("/dashboard/hosts/…"), for the
  // dashboard_url every item carries.
  dashboardUrl: (path: string) => string;
};

export type ToolDeps = {
  log: McpCallLogger;
  limiter: RateLimiter;
  now: () => number;
};

const defaultDeps: ToolDeps = {
  log: logMcpCall,
  limiter: mcpRateLimiter,
  now: () => performance.now(),
};

type ToolSpec<I extends z.ZodObject, O extends z.ZodObject> = {
  name: string;
  title: string;
  description: string;
  input: I;
  output: O;
  run: (args: z.output<I>, ctx: ToolContext) => Promise<z.input<O>>;
  render: (result: z.output<O>) => string;
  // Items returned, for the log's result_items; null when the result isn't
  // a list.
  countItems?: (result: z.output<O>) => number | null;
};

// A tool with its argument and result types erased, for the tool list.
export type McpTool = {
  name: string;
  title: string;
  description: string;
  input: z.ZodObject;
  output: z.ZodObject;
  call: (rawArgs: unknown, ctx: ToolContext, deps?: ToolDeps) => Promise<CallToolResult>;
};

export const TEMPORARY_PASSWORD_MESSAGE =
  "An administrator set a temporary password for this account. Sign in to the upkeep.sh dashboard, " +
  "choose a new password, then try again.";

export const RATE_LIMITED_MESSAGE =
  "Too many upkeep.sh tool calls in the last minute. Wait a minute, then try again.";

const INTERNAL_ERROR_MESSAGE =
  "upkeep.sh hit an internal error running this tool. Try again later.";

function errorResult(message: string): CallToolResult {
  return { isError: true, content: [{ type: "text", text: message }] };
}

function describeIssues(err: z.ZodError): string {
  return err.issues
    .map((i) => (i.path.length ? `${i.path.join(".")}: ${i.message}` : i.message))
    .join("; ");
}

export function defineTool<I extends z.ZodObject, O extends z.ZodObject>(
  spec: ToolSpec<I, O>,
): McpTool {
  return {
    name: spec.name,
    title: spec.title,
    description: spec.description,
    input: spec.input,
    output: spec.output,
    async call(rawArgs, ctx, deps = defaultDeps) {
      const { viewer } = ctx;
      const credentialKey = `${viewer.credential.kind}:${viewer.credential.clientId}:${viewer.userId}`;
      // Not logged: a client stuck in a loop shouldn't also flood the log.
      if (!deps.limiter.hit(credentialKey)) {
        console.warn(`mcp: rate limit hit by ${credentialKey}`);
        return errorResult(RATE_LIMITED_MESSAGE);
      }

      const started = deps.now();
      let loggedArgs: unknown = rawArgs ?? {};
      let result: CallToolResult;
      let resultItems: number | null = null;
      let logError: string | null = null;
      try {
        if (viewer.mustChangePassword) throw new ToolError(TEMPORARY_PASSWORD_MESSAGE);
        const args = spec.input.safeParse(rawArgs ?? {});
        if (!args.success) throw new ToolError(`Invalid arguments: ${describeIssues(args.error)}`);
        loggedArgs = args.data;
        const output = spec.output.parse(await spec.run(args.data, ctx));
        resultItems = spec.countItems?.(output) ?? null;
        result = {
          content: [{ type: "text", text: spec.render(output) }],
          structuredContent: output,
        };
      } catch (err) {
        if (err instanceof ToolError) {
          logError = err.message;
          result = errorResult(err.message);
        } else {
          console.error(`mcp: tool ${spec.name} failed`, err);
          logError =
            (err instanceof Error ? err.message : String(err)).slice(0, 500) || "internal error";
          result = errorResult(INTERNAL_ERROR_MESSAGE);
        }
      }
      // Best effort (read tools): a failed log never fails the call.
      try {
        await deps.log({
          viewer,
          tool: spec.name,
          arguments: loggedArgs,
          resultItems,
          durationMs: deps.now() - started,
          error: logError,
        });
      } catch (err) {
        console.error(`mcp: logging the ${spec.name} call failed`, err);
      }
      return result;
    },
  };
}

export function registerTools(server: McpServer, tools: McpTool[], ctx: ToolContext) {
  for (const tool of tools) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.input,
        outputSchema: tool.output,
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
      },
      (args) => tool.call(args, ctx),
    );
  }
}
