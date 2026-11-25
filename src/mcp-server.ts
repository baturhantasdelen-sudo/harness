#!/usr/bin/env node
/**
 * Standalone stdio MCP server — local heuristic assessment only.
 * No network, no credentials, no VERIFIED outcomes or attestations.
 *
 * Transport: official StdioServerTransport receives only frames that already
 * passed BoundedStdioFrameGate. The SDK ReadBuffer is not given oversized
 * bytes, so those bytes are not UTF-8-decoded or JSON.parsed.
 */
import { PassThrough } from 'node:stream';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { LocalHeuristicAdapter } from './adapters/local-heuristic.js';
import type { HarnessScenario, ScenarioSeverity } from './types.js';

/**
 * Incoming frame body ceiling (not configurable).
 * Byte-count semantics: body bytes exclude the terminating LF (0x0A) and one
 * optional trailing CR (0x0D). A body of exactly this size is forwarded.
 * One additional body byte is rejected before decode/parse.
 * 98304 = 65536 application-argument budget + 32768 JSON-RPC envelope overhead.
 */
export const MCP_STDIO_MAX_FRAME_BYTES = 98_304;

export const MCP_ASSESSMENT_LIMITS = {
  maxTotalArgumentJsonBytes: 65_536,
  maxStringFieldLength: 8_192,
  maxIdFieldLength: 256,
  maxToolArgsDepth: 8,
  maxNestingDepth: 8,
  maxArrayElements: 32,
  maxObjectKeys: 64,
  maxTotalNodes: 128,
  maxToolArgsKeyCount: 64,
} as const;

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;

function logDiagnostic(message: string): void {
  console.error(`[nexus-harness-mcp] ${message}`);
}

export function measureFrameBodyBytes(lineWithoutNewline: Buffer): number {
  if (lineWithoutNewline.length > 0 && lineWithoutNewline[lineWithoutNewline.length - 1] === 0x0d) {
    return lineWithoutNewline.length - 1;
  }
  return lineWithoutNewline.length;
}

/**
 * LF / CRLF frame splitter.
 *
 * Body bytes exclude the delimiter. LF is a delimiter by itself. CR is
 * delimiter material only when the next byte is LF; otherwise that CR is one
 * body byte. A single pending-CR flag is the only extra state, so a CR and LF
 * split across chunks cannot be counted as an extra body byte. The body buffer
 * never grows past maxBodyBytes. Oversized input is dropped before any decode.
 */
export class BoundedStdioFrameGate {
  private pending: Buffer = Buffer.alloc(0);
  private holdCr = false;

  constructor(
    private readonly maxBodyBytes: number,
    private readonly onFrame: (frameWithNewline: Buffer) => void,
    private readonly onReject: (reason: string) => void,
  ) {}

  push(chunk: Buffer): 'ok' | 'reject' {
    let offset = 0;
    while (offset < chunk.length) {
      if (this.holdCr) {
        const next = chunk[offset];
        if (next === 0x0a) {
          this.emit(Buffer.from([0x0d, 0x0a]));
          this.holdCr = false;
          offset += 1;
          continue;
        }
        if (this.pending.length >= this.maxBodyBytes) {
          this.fail('FRAME_BYTE_CEILING_INCOMPLETE');
          return 'reject';
        }
        this.pending = Buffer.concat([this.pending, Buffer.from([0x0d])]);
        this.holdCr = false;
        continue;
      }

      let cursor = offset;
      while (cursor < chunk.length && chunk[cursor] !== 0x0a && chunk[cursor] !== 0x0d) {
        cursor += 1;
      }
      const run = chunk.subarray(offset, cursor);
      if (run.length > 0) {
        if (this.pending.length + run.length > this.maxBodyBytes) {
          this.fail('FRAME_BYTE_CEILING_INCOMPLETE');
          return 'reject';
        }
        this.pending = this.pending.length === 0 ? Buffer.from(run) : Buffer.concat([this.pending, run]);
      }
      if (cursor >= chunk.length) {
        return 'ok';
      }
      if (chunk[cursor] === 0x0a) {
        this.emit(Buffer.from([0x0a]));
        offset = cursor + 1;
        continue;
      }
      this.holdCr = true;
      offset = cursor + 1;
    }
    return 'ok';
  }

  private emit(delimiter: Buffer): void {
    const frame = Buffer.concat([this.pending, delimiter]);
    this.pending = Buffer.alloc(0);
    this.onFrame(frame);
  }

  private fail(reason: string): void {
    this.pending = Buffer.alloc(0);
    this.holdCr = false;
    this.onReject(reason);
  }
}

function rejectUnsupported(value: unknown): void {
  const kind = typeof value;
  if (kind === 'string' || kind === 'boolean') {
    return;
  }
  if (kind === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('UNSUPPORTED_VALUE');
    }
    return;
  }
  if (value === null) {
    return;
  }
  throw new Error('UNSUPPORTED_VALUE');
}

/**
 * Structural budgets run before JSON.stringify and before heuristic evaluation.
 * Traversal is an explicit stack capped by maxTotalNodes.
 */
export function assertToolArgumentsWithinBounds(raw: unknown): void {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('INVALID_TOOL_ARGUMENTS');
  }
  const limits = MCP_ASSESSMENT_LIMITS;
  const stack: Array<{ value: unknown; depth: number }> = [{ value: raw, depth: 1 }];
  let nodes = 0;
  let objectKeys = 0;
  let arrayElements = 0;

  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) {
      break;
    }
    nodes += 1;
    if (nodes > limits.maxTotalNodes) {
      throw new Error('TOO_MANY_NODES');
    }
    if (current.depth > limits.maxNestingDepth) {
      throw new Error('NESTING_TOO_DEEP');
    }
    const { value } = current;
    if (value === null || typeof value !== 'object') {
      if (typeof value === 'string' && value.length > limits.maxStringFieldLength) {
        throw new Error('STRING_FIELD_TOO_LONG');
      }
      rejectUnsupported(value);
      continue;
    }
    if (Array.isArray(value)) {
      if (value.length > limits.maxArrayElements) {
        throw new Error('ARRAY_TOO_LARGE');
      }
      arrayElements += value.length;
      if (arrayElements > limits.maxArrayElements) {
        throw new Error('ARRAY_TOO_LARGE');
      }
      for (let index = value.length - 1; index >= 0; index -= 1) {
        stack.push({ value: value[index], depth: current.depth + 1 });
      }
      continue;
    }
    const keys = Object.keys(value as Record<string, unknown>);
    if (keys.length > limits.maxObjectKeys) {
      throw new Error('TOO_MANY_KEYS');
    }
    objectKeys += keys.length;
    if (objectKeys > limits.maxObjectKeys || objectKeys > limits.maxToolArgsKeyCount) {
      throw new Error('TOO_MANY_KEYS');
    }
    for (let index = keys.length - 1; index >= 0; index -= 1) {
      const key = keys[index];
      if (key.length > limits.maxStringFieldLength) {
        throw new Error('STRING_FIELD_TOO_LONG');
      }
      const child = (value as Record<string, unknown>)[key];
      if (child === undefined) {
        throw new Error('UNSUPPORTED_VALUE');
      }
      stack.push({ value: child, depth: current.depth + 1 });
    }
  }

  const jsonBytes = Buffer.byteLength(JSON.stringify(raw), 'utf8');
  if (jsonBytes > limits.maxTotalArgumentJsonBytes) {
    throw new Error('TOOL_ARGUMENTS_TOO_LARGE');
  }
}

const boundedString = (max: number) =>
  z.string().min(1).max(max, { message: 'STRING_FIELD_TOO_LONG' });

const assessInputSchema = {
  id: boundedString(MCP_ASSESSMENT_LIMITS.maxIdFieldLength),
  name: boundedString(MCP_ASSESSMENT_LIMITS.maxStringFieldLength),
  category: boundedString(MCP_ASSESSMENT_LIMITS.maxStringFieldLength),
  severity: z.enum(SEVERITIES),
  userIntent: boundedString(MCP_ASSESSMENT_LIMITS.maxStringFieldLength),
  toolName: boundedString(MCP_ASSESSMENT_LIMITS.maxStringFieldLength),
  toolArgs: z.record(z.string(), z.unknown()).optional(),
};

const assessShape = z.object({
  id: boundedString(MCP_ASSESSMENT_LIMITS.maxIdFieldLength),
  name: boundedString(MCP_ASSESSMENT_LIMITS.maxStringFieldLength),
  category: boundedString(MCP_ASSESSMENT_LIMITS.maxStringFieldLength),
  severity: z.enum(SEVERITIES),
  userIntent: boundedString(MCP_ASSESSMENT_LIMITS.maxStringFieldLength),
  toolName: boundedString(MCP_ASSESSMENT_LIMITS.maxStringFieldLength),
  toolArgs: z.record(z.string(), z.unknown()).default({}),
});
type AssessInput = z.infer<typeof assessShape>;

export function toHarnessScenario(parsed: AssessInput): HarnessScenario {
  return {
    id: parsed.id,
    name: parsed.name,
    category: parsed.category,
    severity: parsed.severity as ScenarioSeverity,
    userIntent: parsed.userIntent,
    toolName: parsed.toolName,
    toolArgs: parsed.toolArgs ?? {},
  };
}

export async function runMcpStdioServer(): Promise<void> {
  const adapter = new LocalHeuristicAdapter();
  const mcp = new McpServer(
    { name: 'nexus-shield-harness-mcp', version: '0.1.0' },
    {
      capabilities: { tools: {} },
      instructions:
        'Local heuristic assessment for agent actions. Decisions are ALLOW or BLOCK with violation codes only — not production verification or signed attestations.',
    },
  );

  mcp.tool(
    'assess_agent_action',
    'Heuristic security assessment of a proposed agent tool call (local pattern matching only).',
    assessInputSchema,
    {
      title: 'Assess agent action',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
    async (args) => {
      assertToolArgumentsWithinBounds(args);
      const parsed = assessShape.parse(args);
      const scenario = toHarnessScenario(parsed);
      const result = await adapter.evaluate(scenario);
      const decision = result.decision === 'BLOCK' ? 'BLOCK' : 'ALLOW';
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              decision,
              violations: result.violations,
              engine: adapter.name,
            }),
          },
        ],
        isError: false,
      };
    },
  );

  const inbound = new PassThrough();
  let rejected = false;
  const gate = new BoundedStdioFrameGate(
    MCP_STDIO_MAX_FRAME_BYTES,
    (frame) => {
      inbound.write(frame);
    },
    (reason) => {
      rejected = true;
      logDiagnostic(`FRAME_REJECTED_BEFORE_JSON_PARSE ${reason}`);
      inbound.destroy();
    },
  );

  const transport = new StdioServerTransport(inbound, process.stdout);
  transport.onerror = (err) => {
    const text = err instanceof Error ? err.message : String(err);
    logDiagnostic(`JSON_RPC_PARSE_OR_VALIDATION ${text.slice(0, 180)}`);
  };
  await mcp.connect(transport);

  process.stdin.on('data', (chunk: Buffer | string) => {
    if (rejected) {
      return;
    }
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const status = gate.push(bytes);
    if (status === 'reject') {
      process.exitCode = 1;
      process.stdin.destroy();
      process.exit(1);
    }
  });
  process.stdin.on('end', () => {
    if (rejected) {
      return;
    }
    inbound.end();
    setImmediate(() => {
      if (process.exitCode == null) {
        process.exit(0);
      }
    });
  });
  process.stdin.resume();
}

async function main(): Promise<void> {
  try {
    await runMcpStdioServer();
  } catch (err) {
    logDiagnostic(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  }
}

const entry = process.argv[1]?.replace(/\\/g, '/');
if (entry?.endsWith('/mcp-server.js') || entry?.endsWith('/mcp-server.ts')) {
  void main();
}
