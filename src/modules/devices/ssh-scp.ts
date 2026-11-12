import type { ChildProcess } from "node:child_process";

/** Send one server-generated staging file and require all three legacy SCP acknowledgements. */
export function sendScpFile(child: ChildProcess, content: Buffer, filename: string) {
  if (
    !/^soar-[a-f0-9]{32}\.(?:cfg|conf)$/.test(filename) ||
    !content.length ||
    content.length > 20 * 1024 * 1024
  )
    throw new Error("Invalid SCP upload");
  let phase = 0;
  let failure = false;
  const fail = () => {
    failure = true;
    child.kill("SIGKILL");
  };
  child.stdin?.on("error", () => {});
  child.stdout?.on("data", (chunk: Buffer) => {
    for (const byte of chunk) {
      if (failure) return;
      if (byte !== 0 || phase >= 3) return fail();
      phase++;
      if (phase === 1) child.stdin?.write(`C0600 ${content.length} ${filename}\n`);
      else if (phase === 2) {
        child.stdin?.write(content);
        child.stdin?.write(Buffer.from([0]));
      } else child.stdin?.end();
    }
  });
  return () => {
    if (failure || phase !== 3) throw new Error("SCP upload not acknowledged");
  };
}

/** Receive exactly one legacy SCP file, used by FortiOS sys_config. */
export function receiveScpFile(child: ChildProcess, maxBytes: number) {
  let phase: "header" | "data" | "status" | "done" = "header";
  let pending = Buffer.alloc(0);
  let expected = 0;
  let received = 0;
  let failure: Error | undefined;
  const chunks: Buffer[] = [];
  const fail = () => {
    failure = new Error("Incomplete or invalid SCP transfer");
    child.kill("SIGKILL");
  };
  child.stdin?.on("error", () => {});
  child.stdout?.on("data", (chunk: Buffer) => {
    if (failure) return;
    pending = Buffer.concat([pending, chunk]);
    if (pending.length + received > maxBytes + 4096) return fail();
    while (pending.length && !failure) {
      if (phase === "header") {
        const newline = pending.indexOf(10);
        if (newline < 0) {
          if (pending.length > 4096) fail();
          return;
        }
        const header = pending.toString("utf8", 0, newline);
        pending = pending.subarray(newline + 1);
        if (/^T\d+ 0 \d+ 0$/.test(header)) {
          child.stdin?.write(Buffer.from([0]));
          continue;
        }
        const match = /^C[0-7]{4} (\d+) [^\r\n]+$/.exec(header);
        expected = Number(match?.[1]);
        if (!match || !Number.isSafeInteger(expected) || expected < 1 || expected > maxBytes)
          return fail();
        phase = "data";
        child.stdin?.write(Buffer.from([0]));
      } else if (phase === "data") {
        const count = Math.min(expected - received, pending.length);
        chunks.push(Buffer.from(pending.subarray(0, count)));
        received += count;
        pending = pending.subarray(count);
        if (received < expected) return;
        phase = "status";
      } else if (phase === "status") {
        if (pending[0] !== 0) return fail();
        pending = pending.subarray(1);
        phase = "done";
        child.stdin?.end(Buffer.from([0]));
      } else {
        fail();
      }
    }
  });
  child.stdin?.write(Buffer.from([0]));
  return () => {
    if (failure || phase !== "done" || received !== expected)
      throw new Error("SCP transfer incomplete");
    return Buffer.concat(chunks);
  };
}
