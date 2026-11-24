import test from "node:test";
import assert from "node:assert/strict";

import {
  MAX_MCP_BUFFER_BYTES,
  MAX_MCP_FRAME_BYTES,
  MAX_MCP_HEADER_BYTES,
  encodeNdjsonMcpMessage,
  encodeMcpFrame,
  NdjsonMcpMessageFramer,
  MpcMessageFramer,
} from "../src/framing.mjs";

test("NDJSON MCP framing round-trips split and consecutive messages", () => {
  const framer = new NdjsonMcpMessageFramer();
  const seen = [];
  framer.onMessage((message) => seen.push(message));

  const first = encodeNdjsonMcpMessage({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
  });
  const second = encodeNdjsonMcpMessage({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/list",
  });
  framer.push(first.subarray(0, 9));
  framer.push(Buffer.concat([first.subarray(9), second]));
  framer.end();

  assert.deepEqual(seen, [
    { jsonrpc: "2.0", id: 1, method: "initialize" },
    { jsonrpc: "2.0", id: 2, method: "tools/list" },
  ]);
});

test("NDJSON MCP framing rejects blank, malformed, truncated, and oversized input safely", () => {
  assert.throws(
    () => new NdjsonMcpMessageFramer().push(Buffer.from("\n")),
    { message: "Invalid MCP frame" },
  );

  const malformed = new NdjsonMcpMessageFramer();
  assert.throws(
    () => malformed.push(Buffer.from('{"secret":"NDJSON-SECRET",\n')),
    (error) => {
      assert.equal(error.message, "Invalid MCP frame");
      assert.equal(String(error).includes("NDJSON-SECRET"), false);
      return true;
    },
  );

  const truncated = new NdjsonMcpMessageFramer();
  truncated.push(Buffer.from('{"jsonrpc":"2.0"}'));
  assert.throws(() => truncated.end(), { message: "Invalid MCP frame" });

  const oversizedFrame = new NdjsonMcpMessageFramer();
  assert.throws(
    () => oversizedFrame.push(Buffer.from(`${"x".repeat(MAX_MCP_FRAME_BYTES + 1)}\n`)),
    { message: "Invalid MCP frame" },
  );

  const oversizedBuffer = new NdjsonMcpMessageFramer();
  assert.throws(
    () => oversizedBuffer.push(Buffer.alloc(MAX_MCP_BUFFER_BYTES + 1, "x")),
    { message: "Invalid MCP frame" },
  );
});

test("MCP framer emits JSON-RPC messages from Content-Length frames", () => {
  const framer = new MpcMessageFramer();
  const seen = [];
  framer.onMessage((message) => seen.push(message));

  const payload = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  framer.push(Buffer.from(`Content-Length: ${Buffer.byteLength(payload)}\r\n\r\n${payload}`));

  assert.deepEqual(seen, [{ jsonrpc: "2.0", id: 1, method: "tools/list" }]);
});

test("MCP framer handles split frames", () => {
  const framer = new MpcMessageFramer();
  const seen = [];
  framer.onMessage((message) => seen.push(message));

  const payload = JSON.stringify({ jsonrpc: "2.0", id: "abc", result: { tools: [] } });
  const frame = Buffer.from(`Content-Length: ${Buffer.byteLength(payload)}\r\n\r\n${payload}`);
  framer.push(frame.subarray(0, 12));
  framer.push(frame.subarray(12));

  assert.equal(seen.length, 1);
  assert.equal(seen[0].id, "abc");
});

test("encodeMcpFrame creates a valid Content-Length frame", async () => {
  const { encodeMcpFrame } = await import("../src/framing.mjs");
  const message = { jsonrpc: "2.0", id: 7, error: { code: -32000, message: "Blocked" } };
  const frame = encodeMcpFrame(message);

  const framer = new MpcMessageFramer();
  const seen = [];
  framer.onMessage((parsed) => seen.push(parsed));
  framer.push(frame);

  assert.deepEqual(seen, [message]);
});

test("MCP framer rejects oversized headers, frames, and buffers with fixed errors", () => {
  const oversizedHeader = new MpcMessageFramer();
  assert.throws(
    () => oversizedHeader.push(Buffer.from("X".repeat(MAX_MCP_HEADER_BYTES + 1))),
    { message: "Invalid MCP frame" },
  );

  const oversizedFrame = new MpcMessageFramer();
  assert.throws(
    () => oversizedFrame.push(
      Buffer.from(`Content-Length: ${MAX_MCP_FRAME_BYTES + 1}\r\n\r\n`),
    ),
    { message: "Invalid MCP frame" },
  );

  const oversizedBuffer = new MpcMessageFramer();
  assert.throws(
    () => oversizedBuffer.push(Buffer.alloc(MAX_MCP_BUFFER_BYTES + 1)),
    { message: "Invalid MCP frame" },
  );
});

test("MCP framer rejects malformed JSON without exposing parser details", () => {
  const framer = new MpcMessageFramer();
  const malformed = Buffer.from('{"secret":"FRAME-SECRET",');
  assert.throws(
    () => framer.push(Buffer.concat([
      Buffer.from(`Content-Length: ${malformed.length}\r\n\r\n`),
      malformed,
    ])),
    (error) => {
      assert.equal(error.message, "Invalid MCP frame");
      assert.equal(String(error).includes("FRAME-SECRET"), false);
      return true;
    },
  );
});

test("MCP framer rejects truncated headers and bodies at EOF with fixed errors", () => {
  const truncatedHeader = new MpcMessageFramer();
  truncatedHeader.push(Buffer.from("Content-Length: 42\r\nX-Secret: EOF-HEADER-SECRET"));
  assert.throws(
    () => truncatedHeader.end(),
    (error) => {
      assert.equal(error.message, "Invalid MCP frame");
      assert.equal(String(error).includes("EOF-HEADER-SECRET"), false);
      return true;
    },
  );

  const truncatedBody = new MpcMessageFramer();
  truncatedBody.push(Buffer.from(
    "Content-Length: 128\r\n\r\n{\"secret\":\"EOF-BODY-SECRET\"",
  ));
  assert.throws(
    () => truncatedBody.end(),
    (error) => {
      assert.equal(error.message, "Invalid MCP frame");
      assert.equal(String(error).includes("EOF-BODY-SECRET"), false);
      return true;
    },
  );

  const complete = new MpcMessageFramer();
  complete.push(encodeMcpFrame({ jsonrpc: "2.0", id: 1, result: {} }));
  assert.doesNotThrow(() => complete.end());
});
