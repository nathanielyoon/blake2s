/** Combined IVs for hash functions. */
const IV = /* @__PURE__ */ Uint32Array.from(
  /* @__PURE__ */ "428a2f9871374491b5c0fbcfe9b5dba53956c25b59f111f1923f82a4ab1c5ed5d807aa9812835b01243185be550c7dc372be5d7480deb1fe9bdc06a7c19bf174e49b69c1efbe47860fc19dc6240ca1cc2de92c6f4a7484aa5cb0a9dc76f988da983e5152a831c66db00327c8bf597fc7c6e00bf3d5a7914706ca63511429296727b70a852e1b21384d2c6dfc53380d13650a7354766a0abb81c2c92e92722c85a2bfe8a1a81a664bc24b8b70c76c51a3d192e819d6990624f40e3585106aa07019a4c1161e376c082748774c34b0bcb5391c0cb34ed8aa4a5b9cca4f682e6ff3748f82ee78a5636f84c878148cc7020890befffaa4506cebbef9a3f7c67178f2ca273eced186b8c7eada7dd6f57d4f7f06f067aa0a637dc5113f98041b710b3528db77f532caab7b3c9ebe0a431d67c44cc5d4be597f299c5fcb6fab6c44198cd728ae2223ef65cdec4d3b2f8189dbbcf348b538b605d019af194f9bda6d8118a303024245706fbe4ee4b28cd5ffb4e2f27b896f3b1696b125c71235cf6926949ef14ad2384f25e38b8cd5b577ac9c65592b02756ea6e483bd41fbd4831153b5ee66dfab2db4321098fb213fbeef0ee43da88fc2930aa725e003826f0a0e6e7046d22ffc5c26c9265ac42aed9d95b3df8baf63de3c77b2a847edaee61482353b4cf10364bc423001d0f897910654be30d6ef52185565a9105771202a32bbd1b8b8d2d0c85141ab53df8eeb99e19b48a8c5c95a63e3418acb7763e373d6b2b8a35defb2fc43172f60a1f0ab721a6439ec23631e28de82bde9b2c67915e372532bea26619c21c0c207cde0eb1eee6ed17872176fbaa2c898a6bef90dae131c471b23047d8440c7249315c9bebc9c100d4ccb3e42b6fc657e2a3ad6faec4a4758176a09e667f3bcc908bb67ae8584caa73b3c6ef372fe94f82ba54ff53a5f1d36f1510e527fade682d19b05688c2b3e6c1f1f83d9abfb41bd6b5be0cd19137e21796a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd1976543210fedcba986df984ae357b20c1df250c8b491763eaebcd13978f04a562fa427509d386cb1e38b0a6c291ef57d4a4def15cb8293670931ce7bda2684f05803b9ef65a417d2c5167482a0dc3e9bfd951c840fb73ea62cb61fa50e943d872"
    .match(/.{8}/g)!,
  (Z) => parseInt(Z, 16),
);
const SHA_256 = IV.subarray(176, 184);
/** Blake2s compression function. */
const b2_mix = (to: Uint32Array, last: boolean) => {
  to.copyWithin(0, 16, 24), to.set(SHA_256, 8), to[12] ^= to[25];
  to[13] ^= to[26], last && (to[14] = ~to[14]);
  let z = 0, y = 80, x, a, b, c;
  do do x = --y & 3,
    a = IV[(x >> 1 | z << 1 & 2) + 204] >> (x << 4 & 16),
    to[c = a >> 12 & 15] ^= to[a & 15] += to[b = a >> 4 & 15] +
      to[(IV[z + 184] >> (x << 3) & 15) + 27],
    to[b] ^= to[a >> 8 & 15] += to[c] = to[c] >>> 16 | to[c] << 16,
    to[b] = to[b] >>> 12 | to[b] << 20,
    to[c] ^= to[a & 15] += to[b] + to[(IV[z + 184] >> (x << 3) + 4 & 15) + 27],
    to[b] ^= to[a >> 8 & 15] += to[c] = to[c] >>> 8 | to[c] << 24,
    to[b] = to[b] >>> 7 | to[b] << 25; while (x); while (++z < 20);
  do to[x + 16] ^= to[x] ^ to[x + 8]; while (++x < 8);
};
/** Blake2s hasher. */
export class Blake2s {
  /** Internal state. */
  private state = new Uint32Array(43);
  /**
   * Create a new hash instance.
   *
   * @param key For keying the hash, if desired.
   * @param out_len Length of hash output.
   */
  constructor(private out_len = 32, key?: Uint8Array) {
    const key_len = key?.length!;
    this.state.set(SHA_256, 16);
    this.state[16] ^= out_len | key_len << 8 | 0x01010000;
    if (key_len) this.update(key), this.state[24] = 64;
  }
  /**
   * Update the hash state.
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
   * Compute a digest from the current state.
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
