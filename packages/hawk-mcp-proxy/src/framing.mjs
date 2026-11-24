export const MAX_MCP_HEADER_BYTES = 8 * 1024;
export const MAX_MCP_FRAME_BYTES = 4 * 1024 * 1024;
export const MAX_MCP_BUFFER_BYTES = MAX_MCP_FRAME_BYTES + MAX_MCP_HEADER_BYTES + 4;
export const MCP_STDIO_FRAMING_MODES = Object.freeze([
  "ndjson",
  "content-length",
]);

export function normalizeMcpStdioFraming(value = "ndjson") {
  const normalized = String(value ?? "ndjson").trim().toLowerCase();
  if (!MCP_STDIO_FRAMING_MODES.includes(normalized)) {
    throw new Error("Invalid MCP stdio framing mode");
  }
  return normalized;
}

export function createMcpMessageFramer(mode = "ndjson") {
  return normalizeMcpStdioFraming(mode) === "ndjson"
    ? new NdjsonMcpMessageFramer()
    : new MpcMessageFramer();
}

export function encodeMcpMessage(message, mode = "ndjson") {
  return normalizeMcpStdioFraming(mode) === "ndjson"
    ? encodeNdjsonMcpMessage(message)
    : encodeMcpFrame(message);
}

export function encodeNdjsonMcpMessage(message) {
  let serialized;
  try {
    serialized = JSON.stringify(message);
  } catch {
    throw invalidFrameError();
  }
  if (typeof serialized !== "string") {
    throw invalidFrameError();
  }
  const body = Buffer.from(serialized, "utf8");
  if (body.length === 0 || body.length > MAX_MCP_FRAME_BYTES) {
    throw invalidFrameError();
  }
  return Buffer.concat([body, Buffer.from("\n", "utf8")]);
}

export class NdjsonMcpMessageFramer {
  #buffer = Buffer.alloc(0);
  #ended = false;
  #listeners = [];

  onMessage(listener) {
    this.#listeners.push(listener);
  }

  push(chunk) {
    if (this.#ended) {
      throw invalidFrameError();
    }
    const incoming = Buffer.from(chunk);
    if (
      incoming.length > MAX_MCP_BUFFER_BYTES
      || this.#buffer.length > MAX_MCP_BUFFER_BYTES - incoming.length
    ) {
      throw invalidFrameError();
    }
    this.#buffer = Buffer.concat([this.#buffer, incoming]);

    while (true) {
      const lineEnd = this.#buffer.indexOf("\n");
      if (lineEnd === -1) {
        if (this.#buffer.length > MAX_MCP_FRAME_BYTES) {
          throw invalidFrameError();
        }
        return;
      }

      let bodyEnd = lineEnd;
      if (bodyEnd > 0 && this.#buffer[bodyEnd - 1] === 0x0d) {
        bodyEnd -= 1;
      }
      if (bodyEnd === 0 || bodyEnd > MAX_MCP_FRAME_BYTES) {
        throw invalidFrameError();
      }

      const body = this.#buffer.subarray(0, bodyEnd).toString("utf8");
      this.#buffer = this.#buffer.subarray(lineEnd + 1);

      let message;
      try {
        message = JSON.parse(body);
      } catch {
        throw invalidFrameError();
      }
      for (const listener of this.#listeners) {
        listener(message);
      }
    }
  }

  end(chunk) {
    if (this.#ended) {
      throw invalidFrameError();
    }
    if (chunk !== undefined) {
      this.push(chunk);
    }
    this.#ended = true;
    if (this.#buffer.length !== 0) {
      this.#buffer = Buffer.alloc(0);
      throw invalidFrameError();
    }
  }
}

export function encodeMcpFrame(message) {
  const body = Buffer.from(JSON.stringify(message), "utf8");
  if (body.length > MAX_MCP_FRAME_BYTES) {
    throw invalidFrameError();
  }
  return Buffer.concat([
    Buffer.from(`Content-Length: ${body.length}\r\n\r\n`, "utf8"),
    body,
  ]);
}

export class MpcMessageFramer {
  #buffer = Buffer.alloc(0);
  #ended = false;
  #listeners = [];

  onMessage(listener) {
    this.#listeners.push(listener);
  }

  push(chunk) {
    if (this.#ended) {
      throw invalidFrameError();
    }
    const incoming = Buffer.from(chunk);
    if (
      incoming.length > MAX_MCP_BUFFER_BYTES
      || this.#buffer.length > MAX_MCP_BUFFER_BYTES - incoming.length
    ) {
      throw invalidFrameError();
    }
    this.#buffer = Buffer.concat([this.#buffer, incoming]);

    while (true) {
      const headerEnd = this.#buffer.indexOf("\r\n\r\n");
      if (headerEnd === -1) {
        if (this.#buffer.length > MAX_MCP_HEADER_BYTES) {
          throw invalidFrameError();
        }
        return;
      }
      if (headerEnd > MAX_MCP_HEADER_BYTES) {
        throw invalidFrameError();
      }

      const headerText = this.#buffer.subarray(0, headerEnd).toString("utf8");
      const contentLength = parseContentLength(headerText);
      if (
        contentLength === null
        || !Number.isSafeInteger(contentLength)
        || contentLength < 0
        || contentLength > MAX_MCP_FRAME_BYTES
      ) {
        throw invalidFrameError();
      }

      const bodyStart = headerEnd + 4;
      const frameEnd = bodyStart + contentLength;
      if (frameEnd > MAX_MCP_BUFFER_BYTES) {
        throw invalidFrameError();
      }
      if (this.#buffer.length < frameEnd) {
        return;
      }

      const body = this.#buffer.subarray(bodyStart, frameEnd).toString("utf8");
      this.#buffer = this.#buffer.subarray(frameEnd);

      let message;
      try {
        message = JSON.parse(body);
      } catch {
        throw invalidFrameError();
      }
      for (const listener of this.#listeners) {
        listener(message);
      }
    }
  }

  end(chunk) {
    if (this.#ended) {
      throw invalidFrameError();
    }
    if (chunk !== undefined) {
      this.push(chunk);
    }
    this.#ended = true;
    if (this.#buffer.length !== 0) {
      this.#buffer = Buffer.alloc(0);
      throw invalidFrameError();
    }
  }
}

function parseContentLength(headerText) {
  let parsed = null;
  for (const line of headerText.split(/\r\n/)) {
    const match = /^content-length:\s*(\d+)$/i.exec(line.trim());
    if (!match) {
      continue;
    }
    if (parsed !== null) {
      return null;
    }
    parsed = Number(match[1]);
  }
  return parsed;
}

function invalidFrameError() {
  return new Error("Invalid MCP frame");
}
