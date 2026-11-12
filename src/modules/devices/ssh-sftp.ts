import type { ChildProcess } from "node:child_process";

const uint32 = (value: number) => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
};
const string = (bytes: Buffer) => Buffer.concat([uint32(bytes.length), bytes]);

/** Single exclusive-create upload over SFTP v3 (draft-ietf-secsh-filexfer-02, sections 3, 6.3 and 6.4). */
export function sendSftpFile(child: ChildProcess, content: Buffer, filename: string) {
  if (
    !/^soar-[a-f0-9]{32}\.rsc$/.test(filename) ||
    !content.length ||
    content.length > 20 * 1024 * 1024
  )
    throw new Error("Invalid SFTP upload");
  let phase: "version" | "open" | "write" | "close" | "done" = "version";
  let pending = Buffer.alloc(0),
    handle = Buffer.alloc(0);
  let id = 0,
    offset = 0,
    acknowledged = 0;
  let failure = false;
  const fail = () => {
    failure = true;
    child.kill("SIGKILL");
  };
  const send = (type: number, payload: Buffer) => {
    child.stdin?.write(Buffer.concat([uint32(payload.length + 1), Buffer.from([type]), payload]));
  };
  const next = () => {
    id++;
    if (offset >= content.length) {
      phase = "close";
      send(4, Buffer.concat([uint32(id), string(handle)]));
      return;
    }
    const bytes = content.subarray(offset, offset + 32768);
    const position = Buffer.alloc(8);
    position.writeBigUInt64BE(BigInt(offset));
    offset += bytes.length;
    phase = "write";
    send(6, Buffer.concat([uint32(id), string(handle), position, string(bytes)]));
  };
  child.stdin?.on("error", () => {});
  child.stdout?.on("data", (chunk: Buffer) => {
    if (failure) return;
    pending = Buffer.concat([pending, chunk]);
    if (pending.length > 128 * 1024) return fail();
    while (pending.length >= 4 && !failure) {
      const length = pending.readUInt32BE(0);
      if (length < 5 || length > 65536) return fail();
      if (pending.length < length + 4) return;
      const packet = pending.subarray(4, length + 4);
      pending = pending.subarray(length + 4);
      if (phase === "version") {
        if (packet[0] !== 2 || packet.readUInt32BE(1) !== 3) return fail();
        id = 1;
        phase = "open";
        // WRITE | CREAT | EXCL, permissions attribute, mode 0600.
        send(
          3,
          Buffer.concat([
            uint32(id),
            string(Buffer.from(filename)),
            uint32(0x2a),
            uint32(4),
            uint32(0o600),
          ]),
        );
      } else if (phase === "open") {
        if (packet[0] !== 102 || packet.length < 9 || packet.readUInt32BE(1) !== id) return fail();
        const size = packet.readUInt32BE(5);
        if (size < 1 || size > 1024 || packet.length !== 9 + size) return fail();
        handle = Buffer.from(packet.subarray(9));
        next();
      } else if (phase === "write" || phase === "close") {
        if (
          packet[0] !== 101 ||
          packet.length < 17 ||
          packet.readUInt32BE(1) !== id ||
          packet.readUInt32BE(5) !== 0
        )
          return fail();
        const messageLength = packet.readUInt32BE(9);
        const languageOffset = 13 + messageLength;
        if (
          languageOffset + 4 > packet.length ||
          languageOffset + 4 + packet.readUInt32BE(languageOffset) !== packet.length
        )
          return fail();
        if (phase === "close") {
          phase = "done";
          child.stdin?.end();
        } else {
          acknowledged = offset;
          next();
        }
      } else return fail();
    }
  });
  send(1, uint32(3));
  return () => {
    if (failure || phase !== "done" || pending.length || acknowledged !== content.length)
      throw new Error("SFTP upload not acknowledged");
  };
}
