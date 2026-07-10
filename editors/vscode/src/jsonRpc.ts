// SPDX-License-Identifier: Apache-2.0

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";

interface PendingRequest<T = unknown> {
  resolve: (value: T) => void;
  reject: (error: Error) => void;
}

interface JsonRpcResponse {
  id?: unknown;
  result?: unknown;
  error?: {
    code?: unknown;
    message?: unknown;
    data?: unknown;
  };
}

export class JsonRpcResponseError extends Error {
  constructor(
    message: string,
    readonly code?: number,
    readonly data?: unknown,
  ) {
    super(message);
    this.name = "JsonRpcResponseError";
  }
}

export function encodeFrame(message: unknown): Buffer {
  const body = Buffer.from(JSON.stringify(message), "utf8");
  const header = Buffer.from(`Content-Length: ${body.length}\r\n\r\n`, "utf8");
  return Buffer.concat([header, body]);
}

export class FrameDecoder {
  private buffer = Buffer.alloc(0);

  constructor(private readonly onMessage: (message: unknown) => void) {}

  push(chunk: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);

    for (;;) {
      const headerEnd = this.buffer.indexOf("\r\n\r\n");
      if (headerEnd < 0) {
        return;
      }

      const header = this.buffer.subarray(0, headerEnd).toString("utf8");
      const contentLength = parseContentLength(header);
      const bodyStart = headerEnd + 4;
      const bodyEnd = bodyStart + contentLength;
      if (this.buffer.length < bodyEnd) {
        return;
      }

      const body = this.buffer.subarray(bodyStart, bodyEnd).toString("utf8");
      this.onMessage(JSON.parse(body));
      this.buffer = this.buffer.subarray(bodyEnd);
    }
  }
}

export class StdioJsonRpcClient {
  private readonly child: ChildProcessWithoutNullStreams;
  private readonly decoder: FrameDecoder;
  private readonly pending = new Map<number, PendingRequest>();
  private nextId = 1;
  private disposed = false;

  constructor(command: string, args: string[] = [], cwd?: string) {
    this.decoder = new FrameDecoder((message) => this.handleMessage(message));
    this.child = spawn(command, args, {
      cwd,
      stdio: "pipe",
    });
    this.child.stdout.on("data", (chunk: Buffer) => this.decoder.push(chunk));
    this.child.on("error", (error) => this.rejectAll(error));
    this.child.on("exit", (code, signal) => {
      if (!this.disposed) {
        this.rejectAll(
          new Error(`GovFuzz daemon exited code=${code ?? "null"} signal=${signal ?? "null"}`),
        );
      }
    });
  }

  request<T>(method: string, params?: unknown): Promise<T> {
    if (this.disposed) {
      return Promise.reject(new Error("GovFuzz daemon client is disposed"));
    }

    const id = this.nextId++;
    const request = {
      jsonrpc: "2.0",
      id,
      method,
      ...(params === undefined ? {} : { params }),
    };

    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
      });
      this.child.stdin.write(encodeFrame(request), (error) => {
        if (error) {
          this.pending.delete(id);
          reject(error);
        }
      });
    });
  }

  dispose(): void {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.rejectAll(new Error("GovFuzz daemon client disposed"));
    this.child.kill();
  }

  private handleMessage(message: unknown): void {
    if (!isObject(message)) {
      return;
    }
    const response = message as JsonRpcResponse;
    if (typeof response.id !== "number") {
      return;
    }
    const pending = this.pending.get(response.id);
    if (!pending) {
      return;
    }
    this.pending.delete(response.id);

    if (response.error) {
      pending.reject(
        new JsonRpcResponseError(
          typeof response.error.message === "string"
            ? response.error.message
            : "JSON-RPC request failed",
          typeof response.error.code === "number" ? response.error.code : undefined,
          response.error.data,
        ),
      );
      return;
    }

    pending.resolve(response.result);
  }

  private rejectAll(error: Error): void {
    for (const pending of this.pending.values()) {
      pending.reject(error);
    }
    this.pending.clear();
  }
}

function parseContentLength(header: string): number {
  const match = /^Content-Length:\s*(\d+)\s*$/im.exec(header);
  if (!match) {
    throw new Error("JSON-RPC frame is missing Content-Length");
  }
  return Number.parseInt(match[1], 10);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
