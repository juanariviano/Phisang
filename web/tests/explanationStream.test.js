import { test } from "node:test";
import assert from "node:assert/strict";
import { readExplanationStream, readScanStream } from "../src/lib/explanationStream.js";

const encode = (text) => new TextEncoder().encode(text);
const event = (name, value) => `event: ${name}\r\ndata: ${JSON.stringify(value)}\r\n\r\n`;
const response = (body) => new Response(body, { headers: { "content-type": "text/event-stream" } });

test("renders UTF-8 snapshots before the server finishes", async () => {
  let controller;
  let first;
  const appeared = new Promise((resolve) => { first = resolve; });
  const stream = new ReadableStream({ start(c) { controller = c; } });
  const snapshots = [];
  let completed = false;
  const reading = readExplanationStream(response(stream), {
    onSnapshot(value) { snapshots.push(value); first(); },
    onDone() { completed = true; },
  });
  const bytes = encode(event("snapshot", { summary: "Check café", reasons: [], advice: [] }));
  for (const byte of bytes) controller.enqueue(new Uint8Array([byte]));
  await appeared;
  assert.equal(snapshots[0].summary, "Check café");
  assert.equal(completed, false);
  controller.enqueue(encode(event("done", { summary: "Check café carefully", reasons: ["A"], advice: ["B"] })));
  controller.close();
  await reading;
  assert.equal(completed, true);
});

test("an interrupted stream never becomes a completed explanation", async () => {
  let partial = false;
  const body = event("snapshot", { summary: "Partial", reasons: [], advice: [] });
  await assert.rejects(readExplanationStream(response(body), {
    onSnapshot() { partial = true; }, onDone() { assert.fail("Must not complete"); },
  }), /interrupted/);
  assert.equal(partial, true);
});

test("provider error events are readable and retryable", async () => {
  await assert.rejects(readExplanationStream(response(": keepalive\n\n" + event("error", { message: "Please try again." })), {
    onSnapshot() {}, onDone() { assert.fail("Must not complete"); },
  }), /Please try again/);
});

test("cached done responses work without snapshots", async () => {
  let answer;
  await readExplanationStream(response(event("done", { summary: "Saved" })), {
    onSnapshot() { assert.fail("Unexpected snapshot"); }, onDone(value) { answer = value; },
  });
  assert.equal(answer.summary, "Saved");
});

test("scan stages arrive while the result is still pending", async () => {
  let controller, received;
  const updated = new Promise((resolve) => { received = resolve; });
  const stream = new ReadableStream({ start(c) { controller = c; } });
  let result;
  const reading = readScanStream(response(stream), {
    onProgress(value) { received(value); }, onDone(value) { result = value; },
  });
  controller.enqueue(encode(event("progress", { stage: "page", status: "running", label: "Inspecting the website" })));
  assert.equal((await updated).stage, "page");
  assert.equal(result, undefined);
  controller.enqueue(encode(event("done", { scan_id: "finished" })));
  controller.close();
  await reading;
  assert.equal(result.scan_id, "finished");
});
