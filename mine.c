#include <stdio.h>
#include <stdlib.h>

int bc = 0;
unsigned int prevtarget = 0;

// sha
// borrowed from https://github.com/okdshin/PicoSHA2

unsigned int initial_message_digest[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

unsigned int add_constant[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// init sha256
void sha_initstate(unsigned int *state)
{
    int n;

    for (n = 0; n < 8; n++)
    {
        *state = initial_message_digest[n];
        state++;
    }
}

// after init, use this to process the sha256 of the chunk
void sha_processchunk(unsigned int *state, unsigned int *chunk)
{
    unsigned int w[64], s0, s1;
    unsigned int a, b, c, d, e, f, g, h;
    unsigned int t1, t2, maj, ch, S0, S1;
    int n;

    // Read in chunk. When these 32bit words were read, they should have been taken as big endian.
    for (n = 0; n < 16; n++)
        w[n] = *(chunk + n);

    // Extend the sixteen 32-bit words into sixty-four 32-bit words:
    for (n = 16; n < 64; n++)
    {
        s0 = (w[n - 15] >> 7 | w[n - 15] << (32 - 7)) ^ (w[n - 15] >> 18 | w[n - 15] << (32 - 18)) ^ (w[n - 15] >> 3);
        s1 = (w[n - 2] >> 17 | w[n - 2] << (32 - 17)) ^ (w[n - 2] >> 19 | w[n - 2] << (32 - 19)) ^ (w[n - 2] >> 10);
        w[n] = w[n - 16] + s0 + w[n - 7] + s1;
    }

    // Initialize hash value for this chunk:
    a = *(state + 0);
    b = *(state + 1);
    c = *(state + 2);
    d = *(state + 3);
    e = *(state + 4);
    f = *(state + 5);
    g = *(state + 6);
    h = *(state + 7);

    // Main loop:
    for (n = 0; n < 64; n++)
    {
        S0 = (a >> 2 | a << (32 - 2)) ^ (a >> 13 | a << (32 - 13)) ^ (a >> 22 | a << (32 - 22));
        maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;
        S1 = (e >> 6 | e << (32 - 6)) ^ (e >> 11 | e << (32 - 11)) ^ (e >> 25 | e << (32 - 25));
        ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + add_constant[n] + w[n];

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Add this chunk's hash to result so far:
    *(state + 0) += a;
    *(state + 1) += b;
    *(state + 2) += c;
    *(state + 3) += d;
    *(state + 4) += e;
    *(state + 5) += f;
    *(state + 6) += g;
    *(state + 7) += h;
}

// end of sha

unsigned int pad0[12] = {
    0x80000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000280};

unsigned int pad1[8] = {
    0x80000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000100};

int verifyhash(unsigned int *block)
{
    unsigned int state[8];
    unsigned int chunk[16];
    int n;
    unsigned int *u_nonce = ((unsigned int *)block + 16 + 3);

    sha_initstate((unsigned int *)&state);
    // input_block [0-15] make up the first chunk
    for (n = 0; n < 16; n++)
    {
        chunk[n] = *(block + n);
    }
    sha_processchunk((unsigned int *)&state, (unsigned int *)&chunk);

// this is generate a (UN)SAT cnf file from the binary to process with cbmc

#ifdef CBMC
    // makes nonce non-deterministic to recover using sat solver
    *u_nonce = nondet_uint();

// Set nonce range that is satisfiable
#ifdef SATCNF
    // nonce is in the range
    unsigned nonce_start = 497822588 - SATCNF;
    unsigned nonce_end = 497822588 + SATCNF;
    __CPROVER_assume(*u_nonce > nonce_start && *u_nonce < nonce_end); // used nonce should stay in the given range
#else

// Set nonce range that is not satisfiable
#ifdef UNSATCNF
    // nonce is not in the range
    unsigned nonce_start = 497822588;
    unsigned nonce_end = nonce_start + UNSATCNF + UNSATCNF;
    __CPROVER_assume(*u_nonce > nonce_start && *u_nonce < nonce_end); // used nonce should stay in the given range
#else

    /* =============================== GENESIS BLOCK ============================================= */
    // set assumption
    __CPROVER_assume(*u_nonce > 497822587 && *u_nonce < 497822589); // 1 nonces only
    // __CPROVER_assume(*u_nonce > 497822585 && *u_nonce < 497823585); // 1k
    // __CPROVER_assume(*u_nonce > 497822585 && *u_nonce < 497832585); // 10k
    // __CPROVER_assume(*u_nonce > 497822585 && *u_nonce < 497922585); // 100k
    /* =============================== GENESIS BLOCK ============================================= */

    /* =============================== BLOCK 218430 ============================================== */
    // __CPROVER_assume(*u_nonce > 4043570728 && *u_nonce < 4043570731);
    /* =============================== BLOCK 218430 ============================================== */

#endif // else UNSATCNF
#endif // else SATCNF
#endif

    // input_block[16-19] + padding = 2nd chunk
    for (n = 0; n < 4; n++)
    {
        chunk[n] = *(block + 16 + n);
    }
    for (n = 4; n < 16; n++)
        chunk[n] = pad0[n - 4];

    sha_processchunk((unsigned int *)&state, (unsigned int *)&chunk);

    // bitcoin uses sha256(sha256(x)), 2 x hash
    // copy hash into chunk buffer with padding and repeat sha
    for (n = 0; n < 8; n++)
        chunk[n] = state[n];
    for (n = 8; n < 16; n++)
        chunk[n] = pad1[n - 8];

    sha_initstate((unsigned int *)&state);
    sha_processchunk((unsigned int *)&state, (unsigned int *)&chunk);


// setting assumptions for the hash based on the target
#ifdef CBMC
    /* =============================== GENESIS BLOCK ============================================= */
    // encode structure of hash below target with leading zeros
    __CPROVER_assume(
        (unsigned char)(state[7] & 0xff) == 0x00 &&
        (unsigned char)((state[7] >> 8) & 0xff) == 0x00 &&
        (unsigned char)((state[7] >> 16) & 0xff) == 0x00); //&&
        // (unsigned char)((state[7]>>24) & 0xff) == 0x00);

    int flag = 0;
    if ((unsigned char)((state[7] >> 24) & 0xff) != 0x00)
        flag = 1;

    // counterexample will contain an additional leading 0 in the hash which makes it below target
    assert(flag == 1);
#endif

// print hash
#ifndef CBMC
    // printing in reverse, because bitcoin hash is big endian
    for (n = 7; n >= 0; n--)
    {
        printf("%02x-", state[n] & 0xff);
        printf("%02x-", (state[n] >> 8) & 0xff);
        printf("%02x-", (state[n] >> 16) & 0xff);
        printf("%02x-", (state[n] >> 24) & 0xff);
    }
    printf("\n");
#endif

    return (0);
}

// input
unsigned int input_block[20] = {};

int main(int argc, char **argv)
{
    verifyhash(&input_block[0]);
    return 0;
}
