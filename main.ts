const IV = /* @__PURE__ */ Uint32Array.from(
  /* @__PURE__ */ "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd1976543210fedcba986df984ae357b20c1df250c8b491763eaebcd13978f04a562fa427509d386cb1e38b0a6c291ef57d4a4def15cb8293670931ce7bda2684f05803b9ef65a417d2c5167482a0dc3e9bfd951c840fb73ea62cb61fa50e943d872"
    .match(/.{8}/g)!,
  (Z) => parseInt(Z, 16),
);
/** Blake2s compression function. */
const b2_mix = (to: Uint32Array, last: boolean) => {
  to.copyWithin(0, 16, 24), to.set(IV.subarray(0, 8), 8), to[12] ^= to[25];
  to[13] ^= to[26], last && (to[14] = ~to[14]);
  let z = 0, y = 80, x, a, b, c;
  do do x = --y & 3,
    a = IV[(x >> 1 | z << 1 & 2) + 28] >> (x << 4 & 16),
    to[c = a >> 12 & 15] ^= to[a & 15] += to[b = a >> 4 & 15] +
      to[(IV[z + 8] >> (x << 3) & 15) + 27],
    to[b] ^= to[a >> 8 & 15] += to[c] = to[c] >>> 16 | to[c] << 16,
    to[b] = to[b] >>> 12 | to[b] << 20,
    to[c] ^= to[a & 15] += to[b] + to[(IV[z + 8] >> (x << 3) + 4 & 15) + 27],
    to[b] ^= to[a >> 8 & 15] += to[c] = to[c] >>> 8 | to[c] << 24,
    to[b] = to[b] >>> 7 | to[b] << 25; while (x); while (++z < 20);
  do to[x + 16] ^= to[x] ^ to[x + 8]; while (++x < 8);
};
/** Blake2s hasher. */
export class Blake2s {
  private state = new Uint32Array(43);
  /**
   * Creates a new hash instance.
   *
   * @param key For keying the hash, if desired.
   * @param out_len Length of hash output.
   */
  constructor(private out_len = 32, key?: Uint8Array) {
    const key_len = key?.length!;
    this.state.set(IV.subarray(0, 8), 16);
    this.state[16] ^= out_len | key_len << 8 | 0x01010000;
    if (key_len) this.update(key), this.state[24] = 64;
  }
  /**
   * Updates the hash state.
   *
   * @param data Buffer to add.
   * @returns Hash instance, for method chaining.
   */
  update(data: Uint8Array) {
    for (let z = 0; z < data.length; ++z) {
      if (this.state[24] === 64) {
        this.state[25] += 64, this.state[25] < 64 && ++this.state[26];
        b2_mix(this.state, false), this.state[24] = 0;
      }
      const a = this.state[24] << 3 & 24, b = ++this.state[24] + 107 >> 2;
      this.state[b] = this.state[b] & ~(255 << a) | data[z] << a & (255 << a);
    }
    return this;
  }
  /**
   * Computes a digest from the current state.
   *
   * @param into Buffer to fill with hash.
   * @returns Hash value.
   */
  finalize(into?: Uint8Array) {
    const out = new Uint8Array(this.out_len);
    const view = new DataView(this.state.buffer), len = this.state[24] + 108;
    this.state.fill(0, len + 3 >> 2)[25] += this.state[24];
    this.state[25] < this.state[24] && ++this.state[26];
    len & 3 && view.setUint8(len, 0);
    (len ^ len >> 1) & 1 && view.setUint8(len + 1, 0);
    len & 1 & ~len >> 1 && view.setUint8(len + 2, 0);
    b2_mix(this.state, true);
    for (let z = 0; z < this.out_len; ++z) {
      out[z] = this.state[z + 64 >> 2] >> (z << 3 & 24);
    }
    if (into) return into.set(out.subarray(0, into.length)), into;
    return out;
  }
}
