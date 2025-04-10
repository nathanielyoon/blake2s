import { assertEquals } from "@std/assert";
import { Blake2s } from "../main.ts";

const b_s16 = (bin: Uint8Array) =>
  bin.reduce((Z, Y) => Z + Y.toString(16).padStart(2, "0"), "");
const s16_b = (hex: string) =>
  Uint8Array.from(hex.match(/../g) ?? [], (Z) => parseInt(Z, 16));
Deno.test(async function rfc7693() {
  const rfc = await Deno.readTextFile(
    import.meta.url.slice(7, -8) + "/rfc7693.txt",
  );
  const len = Uint16Array.from(rfc.slice(52707, 52793).match(/ \d+/g)!, Number);
  const buffer = new Uint8Array(1056), hash = new Blake2s();
  let z = 0, y = 0, x = 0;
  do do do {
    const a = (x & 1) ^ 1, b = len[z], c = len[y % 6 + 4], e = a ? c : b;
    for (let w = 0, f = 0xDEAD4BAD * e | 0, g = 1, h; w < e; ++w) {
      h = f + g | 0, f = g, g = h, buffer[w + (-a & 32)] = h >> 24;
    }
    hash.update(
      new Blake2s(b, buffer.subarray(0, -(x & 1) & len[z]))
        .update(buffer.subarray(32, c + 32)).finalize(),
    );
  } while (++x & 1); while (++y % 6); while (++z < 4);
  assertEquals(
    hash.finalize().join(""),
    Uint8Array.from(rfc.slice(52411, 52634).split(/\s*,\s*/), Number).join(""),
  );
});

Deno.test(async function python() {
  const bytes = new Uint8Array(512);
  let z = 0;
  do assertEquals(
    s16_b(new TextDecoder().decode(
      (await new Deno.Command("python3", {
        args: [
          "-c",
          `import sys
import hashlib
hash = hashlib.blake2s()
hash.update(bytes.fromhex(sys.argv[1]))
print(hash.digest().hex())`,
          b_s16(crypto.getRandomValues(bytes.subarray(z))),
        ],
      }).output()).stdout,
    )),
    new Blake2s().update(bytes.subarray(z)).finalize(
      z & 1 ? new Uint8Array(32) : undefined,
    ),
  ); while ((z += 99) < bytes.length);
});
