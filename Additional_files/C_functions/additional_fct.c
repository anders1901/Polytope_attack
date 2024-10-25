#include "additional_fct.h"
#include "fips202.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "rounding.h"
#include "symmetric.h"
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MARKER_LEN 50

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int FindMarker(FILE *infile, const char *marker) {
  char line[MAX_MARKER_LEN];
  int i, len;
  int curr_line;

  len = (int)strlen(marker);
  if (len > MAX_MARKER_LEN - 1)
    len = MAX_MARKER_LEN - 1;

  for (i = 0; i < len; i++) {
    curr_line = fgetc(infile);
    line[i] = curr_line;
    if (curr_line == EOF)
      return 0;
  }
  line[len] = '\0';

  while (1) {
    if (!strncmp(line, marker, len))
      return 1;

    for (i = 0; i < len - 1; i++)
      line[i] = line[i + 1];
    curr_line = fgetc(infile);
    line[len - 1] = curr_line;
    if (curr_line == EOF)
      return 0;
    line[len] = '\0';
  }

  // shouldn't get here
  return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int ReadHex(FILE *infile, unsigned char *a, int Length, char *str) {
  int i, ch, started;
  unsigned char ich;

  if (Length == 0) {
    a[0] = 0x00;
    return 1;
  }
  memset(a, 0x00, Length);
  started = 0;
  if (FindMarker(infile, str))
    while ((ch = fgetc(infile)) != EOF) {
      if (!isxdigit(ch)) {
        if (!started) {
          if (ch == '\n')
            break;
          else
            continue;
        } else
          break;
      }
      started = 1;
      if ((ch >= '0') && (ch <= '9'))
        ich = ch - '0';
      else if ((ch >= 'A') && (ch <= 'F'))
        ich = ch - 'A' + 10;
      else if ((ch >= 'a') && (ch <= 'f'))
        ich = ch - 'a' + 10;
      else // shouldn't ever get here
        ich = 0;

      for (i = 0; i < Length - 1; i++)
        a[i] = (a[i] << 4) | (a[i + 1] >> 4);
      a[Length - 1] = (a[Length - 1] << 4) | ich;
    }
  else
    return 0;

  return 1;
}

void fprintBstr(FILE *fp, char *s, unsigned char *a, unsigned long long l) {
  unsigned long long i;

  fprintf(fp, "%s", s);

  for (i = 0; i < l; i++)
    fprintf(fp, "%02X", a[i]);

  if (l == 0)
    fprintf(fp, "00");

  fprintf(fp, "\n");
}

void fprintBstr2(FILE *fp, int b, char *s, unsigned char *a,
                 unsigned long long l) {
  unsigned long long i;

  fprintf(fp, "%s", s);

  for (i = 0; i < l; i++)
    fprintf(fp, "%02X", a[i]);

  if (l == 0)
    fprintf(fp, "00");

  fprintf(fp, ";%d", b);
  fprintf(fp, "\n");
}

/* FUNCTIONS ADDED FOR OUR ATTACK */
/*************************************************
 * Name:        poly_2gamma2
 *
 * Description: Multiply polynomial by 2*GAMMA2 without modular reduction.
 *Assumes input coefficients to be less than 2^{31-D} in absolute value.
 *
 * Arguments:   - poly *a: pointer to input/output polynomial
 **************************************************/
void poly_2gamma2(poly *a) {
  unsigned int i;

  for (i = 0; i < N; ++i)
    a->coeffs[i] = (a->coeffs[i]) * (2 * GAMMA2);
}

/*************************************************
 * Name:        polyveck_2gamma2
 *
 * Description: Multiply vector of polynomials of Length K by 2*GAMMA2 without
 *modular reduction. Assumes input coefficients to be less than 2^{31-D}.
 *
 * Arguments:   - polyveck *v: pointer to input/output vector
 **************************************************/
void polyveck_2gamma2(polyveck *v) {
  unsigned int i;

  for (i = 0; i < K; ++i)
    poly_2gamma2(&v->vec[i]);
}

/*************************************************
 * Name:        poly_make_hint_spec
 *
 * Description: Compute hint polynomial according to the spec. The coefficients
 *              of which indicate whether the low bits of the corresponding
 *              coefficient of the input polynomial overflow into the high bits.
 *
 * Arguments:   - poly *h: pointer to output hint polynomial
 *              - const poly *a0: pointer to low part of input polynomial
 *              - const poly *a1: pointer to high part of input polynomial
 *
 * Returns number of 1 bits.
 **************************************************/
unsigned int poly_make_hint_spec(poly *h, const poly *a0, const poly *a1) {
  unsigned int i, s = 0;
  poly r1, r0, v1, v0;

  for (i = 0; i < N; ++i) {
    r1.coeffs[i] = decompose(&r0.coeffs[i], a1->coeffs[i]);
    v1.coeffs[i] = decompose(&v0.coeffs[i], a0->coeffs[i]);

    if (r1.coeffs[i] != v1.coeffs[i]) {
      h->coeffs[i] = 1;
      s += h->coeffs[i];
    } else {
      h->coeffs[i] = 0;
    }
  }

  return s;
}

/*************************************************
 * Name:        polyveck_make_hint_spec
 *
 * Description: Compute hint vector according to the specification of Dilithium.
 *
 * Arguments:   - polyveck *h: pointer to output vector
 *              - const polyveck *v0: pointer to low part of input vector
 *              - const polyveck *v1: pointer to high part of input vector
 *
 * Returns number of 1 bits.
 **************************************************/
unsigned int polyveck_make_hint_spec(polyveck *h, const polyveck *v0,
                                     const polyveck *v1) {
  unsigned int i, s = 0;

  for (i = 0; i < K; ++i)
    s += poly_make_hint_spec(&h->vec[i], &v0->vec[i], &v1->vec[i]);

  return s;
}

/*************************************************
 * Name:        crypto_sign_signature_spec
 *
 * Description: Computes signature according to specification.
 *
 * Arguments:   - uint8_t *sig:   pointer to output signature (of length
 *CRYPTO_BYTES)
 *              - size_t *siglen: pointer to output length of signature
 *              - uint8_t *m:     pointer to message to be signed
 *              - size_t mlen:    length of message
 *              - uint8_t *ctx:   pointer to context string
 *              - size_t ctxlen:  length of context string
 *              - uint8_t *sk:    pointer to bit-packed secret key
 *
 * Returns 0 (success) or -1 (context string too long)
 **************************************************/
int crypto_sign_signature_spec(uint8_t *sig, size_t *siglen, const uint8_t *m,
                               size_t mlen, const uint8_t *ctx, size_t ctxlen,
                               const uint8_t *sk) {
  unsigned int n;
  uint8_t seedbuf[2 * SEEDBYTES + TRBYTES + RNDBYTES + 2 * CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime, *rnd;
  uint16_t nonce = 0;
  polyvecl mat[K], s1, y, z;
  polyveck t0, s2, w, w1, w0, h, r, r1, r0, ct0, mh;
  poly cp;
  keccak_state state;

  if (ctxlen > 255)
    return -1;

  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + TRBYTES;
  rnd = key + SEEDBYTES;
  mu = rnd + RNDBYTES;
  rhoprime = mu + CRHBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  /* Compute mu = CRH(tr, 0, ctxlen, ctx, msg) */
  mu[0] = 0;
  mu[1] = ctxlen;
  shake256_init(&state);
  shake256_absorb(&state, tr, TRBYTES);
  shake256_absorb(&state, mu, 2);
  shake256_absorb(&state, ctx, ctxlen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
  randombytes(rnd, RNDBYTES);
#else
  for (n = 0; n < RNDBYTES; n++)
    rnd[n] = 0;
#endif
  shake256(rhoprime, CRHBYTES, key, SEEDBYTES + RNDBYTES + CRHBYTES);

  /* Expand matrix and transform vectors */
  polyvec_matrix_expand(mat, rho);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);

rej:
  /* Sample intermediate vector y */
  polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

  /* Matrix-vector multiplication */
  z = y;
  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w, mat, &z);
  polyveck_reduce(&w);
  polyveck_invntt_tomont(&w);

  /* Decompose w and call the random oracle */
  polyveck_caddq(&w);
  polyveck_decompose(&w1, &w0, &w);
  polyveck_pack_w1(sig, &w1);

  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, sig, K * POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, CTILDEBYTES, &state);
  poly_challenge(&cp, sig);
  poly_ntt(&cp);

  /* Compute z, reject if it reveals secret */
  polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
  polyvecl_invntt_tomont(&z);
  polyvecl_add(&z, &z, &y);
  polyvecl_reduce(&z);
  if (polyvecl_chknorm(&z, GAMMA1 - BETA))
    goto rej;

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  polyveck_invntt_tomont(&h);
  polyveck_sub(&r, &w, &h);
  polyveck_caddq(&r);
  polyveck_decompose(&r1, &r0, &r);
  polyveck_reduce(&r0);
  if (polyveck_chknorm(&r0, GAMMA2 - BETA))
    goto rej;

  /* Compute hints for w1 */
  polyveck_pointwise_poly_montgomery(&ct0, &cp, &t0);
  polyveck_invntt_tomont(&ct0);
  polyveck_reduce(&ct0);
  if (polyveck_chknorm(&ct0, GAMMA2))
    goto rej;

  /* We add w - cs2 and ct0*/
  polyveck_add(&mh, &r, &ct0);
  n = polyveck_make_hint_spec(&h, &r, &mh);
  if (n > OMEGA)
    goto rej;

  /* Write signature */
  pack_sig(sig, sig, &z, &h);
  *siglen = CRYPTO_BYTES;
  return 0;
}

/*************************************************
 * Name:        crypto_sign_signature_spec_r0_norm_faulted
 *
 * Description: Computes signature according to specification with r0 norm
 *commented to simulate fault.
 *
 * Arguments:   - uint8_t *sig:   pointer to output signature (of length
 *CRYPTO_BYTES)
 *              - size_t *siglen: pointer to output length of signature
 *              - uint8_t *m:     pointer to message to be signed
 *              - size_t mlen:    length of message
 *              - uint8_t *ctx:   pointer to context string
 *              - size_t ctxlen:  length of context string
 *              - uint8_t *sk:    pointer to bit-packed secret key
 *
 * Returns 0 (success) or -1 (context string too long)
 **************************************************/
int crypto_sign_signature_spec_r0_norm_faulted(uint8_t *sig, size_t *siglen,
                                               const uint8_t *m, size_t mlen,
                                               const uint8_t *ctx,
                                               size_t ctxlen,
                                               const uint8_t *sk) {
  unsigned int n;
  uint8_t seedbuf[2 * SEEDBYTES + TRBYTES + RNDBYTES + 2 * CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime, *rnd;
  uint16_t nonce = 0;
  polyvecl mat[K], s1, y, z;
  polyveck t0, s2, w, w1, w0, h, r, r1, r0, ct0, mh;
  poly cp;
  keccak_state state;

  if (ctxlen > 255)
    return -1;

  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + TRBYTES;
  rnd = key + SEEDBYTES;
  mu = rnd + RNDBYTES;
  rhoprime = mu + CRHBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  /* Compute mu = CRH(tr, 0, ctxlen, ctx, msg) */
  mu[0] = 0;
  mu[1] = ctxlen;
  shake256_init(&state);
  shake256_absorb(&state, tr, TRBYTES);
  shake256_absorb(&state, mu, 2);
  shake256_absorb(&state, ctx, ctxlen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
  randombytes(rnd, RNDBYTES);
#else
  for (n = 0; n < RNDBYTES; n++)
    rnd[n] = 0;
#endif
  shake256(rhoprime, CRHBYTES, key, SEEDBYTES + RNDBYTES + CRHBYTES);

  /* Expand matrix and transform vectors */
  polyvec_matrix_expand(mat, rho);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);

rej:
  /* Sample intermediate vector y */
  polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

  /* Matrix-vector multiplication */
  z = y;
  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w, mat, &z);
  polyveck_reduce(&w);
  polyveck_invntt_tomont(&w);

  /* Decompose w and call the random oracle */
  polyveck_caddq(&w);
  polyveck_decompose(&w1, &w0, &w);
  polyveck_pack_w1(sig, &w1);

  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, sig, K * POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, CTILDEBYTES, &state);
  poly_challenge(&cp, sig);
  poly_ntt(&cp);

  /* Compute z, reject if it reveals secret */
  polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
  polyvecl_invntt_tomont(&z);
  polyvecl_add(&z, &z, &y);
  polyvecl_reduce(&z);
  if (polyvecl_chknorm(&z, GAMMA1 - BETA))
    goto rej;

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  polyveck_invntt_tomont(&h);
  polyveck_sub(&r, &w, &h);
  polyveck_caddq(&r);
  polyveck_decompose(&r1, &r0, &r);
  polyveck_reduce(&r0);
  /* This line is commented to simulate a fault (e.g., clock/voltage-glitch
  producing skipping fault). Here, such a fault can bypass the branching on the
  'if', thus skipping: if (polyveck_chknorm(&r0, GAMMA2 - BETA)) goto rej;
  */

  /* Compute hints for w1 */
  polyveck_pointwise_poly_montgomery(&ct0, &cp, &t0);
  polyveck_invntt_tomont(&ct0);
  polyveck_reduce(&ct0);
  if (polyveck_chknorm(&ct0, GAMMA2))
    goto rej;

  /* We add w - cs2 and ct0*/
  polyveck_add(&mh, &r, &ct0);
  n = polyveck_make_hint_spec(&h, &r, &mh);
  if (n > OMEGA)
    goto rej;

  /* Write signature */
  pack_sig(sig, sig, &z, &h);
  *siglen = CRYPTO_BYTES;
  return 0;
}

/*************************************************
 * Name:        crypto_sign_signature_r0_norm_faulted
 *
 * Description: Computes signature according to implementation with r0 norm
 *              commented to simulate fault.
 *
 * Arguments:   - uint8_t *sig:   pointer to output signature (of length
 *CRYPTO_BYTES)
 *              - size_t *siglen: pointer to output length of signature
 *              - uint8_t *m:     pointer to message to be signed
 *              - size_t mlen:    length of message
 *              - uint8_t *sk:    pointer to bit-packed secret key
 *
 * Returns 0 (success)
 **************************************************/
int crypto_sign_signature_r0_norm_faulted(uint8_t *sig, size_t *siglen,
                                          const uint8_t *m, size_t mlen,
                                          const uint8_t *ctx, size_t ctxlen,
                                          const uint8_t *sk) {
  unsigned int n;
  uint8_t seedbuf[2 * SEEDBYTES + TRBYTES + RNDBYTES + 2 * CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime, *rnd;
  uint16_t nonce = 0;
  polyvecl mat[K], s1, y, z;
  polyveck t0, s2, w1, w0, h;
  poly cp;
  keccak_state state;

  if (ctxlen > 255)
    return -1;

  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + TRBYTES;
  rnd = key + SEEDBYTES;
  mu = rnd + RNDBYTES;
  rhoprime = mu + CRHBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  /* Compute mu = CRH(tr, 0, ctxlen, ctx, msg) */
  mu[0] = 0;
  mu[1] = ctxlen;
  shake256_init(&state);
  shake256_absorb(&state, tr, TRBYTES);
  shake256_absorb(&state, mu, 2);
  shake256_absorb(&state, ctx, ctxlen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
  randombytes(rnd, RNDBYTES);
#else
  for (n = 0; n < RNDBYTES; n++)
    rnd[n] = 0;
#endif
  shake256(rhoprime, CRHBYTES, key, SEEDBYTES + RNDBYTES + CRHBYTES);

  /* Expand matrix and transform vectors */
  polyvec_matrix_expand(mat, rho);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);

rej:
  /* Sample intermediate vector y */
  polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

  /* Matrix-vector multiplication */
  z = y;
  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Decompose w and call the random oracle */
  polyveck_caddq(&w1);
  polyveck_decompose(&w1, &w0, &w1);
  polyveck_pack_w1(sig, &w1);

  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, sig, K * POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, CTILDEBYTES, &state);
  poly_challenge(&cp, sig);
  poly_ntt(&cp);

  /* Compute z, reject if it reveals secret */
  polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
  polyvecl_invntt_tomont(&z);
  polyvecl_add(&z, &z, &y);
  polyvecl_reduce(&z);
  if (polyvecl_chknorm(&z, GAMMA1 - BETA))
    goto rej;

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  polyveck_invntt_tomont(&h);
  polyveck_sub(&w0, &w0, &h);
  polyveck_reduce(&w0);
  /* This line is commented to simulate a fault (e.g., clock/voltage-glitch
  producing skipping fault). Here, such a fault can bypass the branching on the
  'if', thus skipping: if(polyveck_chknorm(&w0, GAMMA2 - BETA)) goto rej;
  */

  /* Compute hints for w1 */
  polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
  polyveck_invntt_tomont(&h);
  polyveck_reduce(&h);
  if (polyveck_chknorm(&h, GAMMA2))
    goto rej;

  polyveck_add(&w0, &w0, &h);
  n = polyveck_make_hint(&h, &w0, &w1);
  if (n > OMEGA)
    goto rej;

  /* Write signature */
  pack_sig(sig, sig, &z, &h);
  *siglen = CRYPTO_BYTES;
  return 0;
}

/*************************************************
 * Name:        test_coefficient_w1_different
 *
 * Description: Verifies signature.
 *
 * Arguments:   - uint8_t *m: pointer to input signature
 *              - size_t siglen: length of signature
 *              - const uint8_t *m: pointer to message
 *              - size_t mlen: length of message
 *              - const uint8_t *pk: pointer to bit-packed public key
 *
 * Returns 0 if signature could be verified correctly and -1 otherwise
 **************************************************/
int test_coefficient_w1_different(const uint8_t *sig, size_t siglen,
                                  const uint8_t *m, size_t mlen,
                                  const uint8_t *ctx, size_t ctxlen,
                                  int32_t *index) {
  unsigned int i;
  uint8_t buf[K * POLYW1_PACKEDBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t mu[CRHBYTES];
  uint8_t c[CTILDEBYTES];
  uint8_t c2[CTILDEBYTES];
  poly cp;
  polyvecl mat[K], z;
  polyveck t1, w1, h;
  keccak_state state;

  int32_t poly_, coef_;
  polyveck w1_test;
  int32_t counter = 0;
  uint8_t flag = 0;
  int8_t pm = 0;

  if (ctxlen > 255 || siglen != CRYPTO_BYTES)
    return -1;

  unpack_pk(rho, &t1, pk);
  if (unpack_sig(c, &z, &h, sig))
    return -1;
  if (polyvecl_chknorm(&z, GAMMA1 - BETA))
    return -1;

  /* Compute CRH(H(rho, t1), msg) */
  shake256(mu, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_init(&state);
  shake256_absorb(&state, mu, TRBYTES);
  mu[0] = 0;
  mu[1] = ctxlen;
  shake256_absorb(&state, mu, 2);
  shake256_absorb(&state, ctx, ctxlen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(&cp, c);
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  poly_ntt(&cp);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Reconstruct w1 */
  polyveck_caddq(&w1);
  polyveck_use_hint(&w1, &w1, &h);

  // Backup our w1 for exhaustive search on the k \times n coefficients
  for (poly_ = 0; poly_ < K; poly_++) {
    for (coef_ = 0; coef_ < N; coef_++) {
      w1_test.vec[poly_].coeffs[coef_] = w1.vec[poly_].coeffs[coef_];
    }
  }

  // Exhaustive search on the k \times n coefficients of w_1'
  for (poly_ = 0; poly_ < K; poly_++) {
    for (coef_ = 0; coef_ < N; coef_++) {
      counter = 0;
      w1_test.vec[poly_].coeffs[coef_] =
          test_value_pm(w1.vec[poly_].coeffs[coef_], 1);
      polyveck_pack_w1(buf, &w1_test);

      /* Call random oracle and verify challenge */
      shake256_init(&state);
      shake256_absorb(&state, mu, CRHBYTES);
      shake256_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
      shake256_finalize(&state);
      shake256_squeeze(c2, CTILDEBYTES, &state);

      // We test if we have the same c or not
      flag = test_equality_c(c, c2);
      if (flag == 0) {
        // break;
        w1_test.vec[poly_].coeffs[coef_] =
            test_value_pm(w1.vec[poly_].coeffs[coef_], 0);
        polyveck_pack_w1(buf, &w1_test);

        /* Call random oracle and verify challenge */
        shake256_init(&state);
        shake256_absorb(&state, mu, CRHBYTES);
        shake256_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
        shake256_finalize(&state);
        shake256_squeeze(c2, CTILDEBYTES, &state);

        // We test if we have the same c or not
        flag = test_equality_c(c, c2);
        if (flag == 0) {
          w1_test.vec[poly_].coeffs[coef_] = w1.vec[poly_].coeffs[coef_];
        } else {
          pm = -2;
          (*index) = poly_ * N + coef_;
          return pm;
        }
      } else {
        pm = -3;
        (*index) = poly_ * N + coef_;
        return pm;
      }
    }
  }
  return -1;
}


/*************************************************
 * Name:        compute_Az_minus_ct
 *
 * Description: Verifies signature.
 *
 * Arguments:   - uint8_t *m: pointer to input signature
 *              - size_t siglen: length of signature
 *              - const uint8_t *m: pointer to message
 *              - size_t mlen: length of message
 *              - const uint8_t *pk: pointer to bit-packed public key
 *
 * Returns 0 if signature could be verified correctly and -1 otherwise
 **************************************************/
int compute_Az_minus_ct(const uint8_t *sig, size_t siglen, const uint8_t *m,
                        size_t mlen, const uint8_t *pk, polyveck *t0,
                        uint8_t *r1, uint8_t *r0) {
  unsigned int i, j;
  uint8_t buf[K * POLYW1_PACKEDBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t mu[CRHBYTES];
  uint8_t c[SEEDBYTES];
  uint8_t c2[SEEDBYTES];
  poly cp;
  polyvecl mat[K], z;
  polyveck t1, w1, w0, h;
  keccak_state state;

  if (siglen != CRYPTO_BYTES)
    return -4;

  unpack_pk(rho, &t1, pk);
  if (unpack_sig(c, &z, &h, sig))
    return -3;
  if (polyvecl_chknorm(&z, GAMMA1 - BETA))
    return -2;

  /* Compute CRH(H(rho, t1), msg) */
  shake256(mu, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_init(&state);
  shake256_absorb(&state, mu, SEEDBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(&cp, c);
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  poly_ntt(&cp);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);
  polyveck_sub(&w1, &w1, &t1);

  polyveck_ntt(t0);
  polyveck_pointwise_poly_montgomery(t0, &cp, t0);
  polyveck_sub(&w1, &w1, t0);

  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Reconstruct w1 */
  polyveck_caddq(&w1);
  polyveck_decompose(&w1, &w0, &w1);

  polyveck_pack_w1(r1, &w1);
  for (i = 0; i < K; i++) {
    printf("[");
    for (j = 0; j < N - 1; j++) {
      printf("%d, ", w0.vec[i].coeffs[j]);
    }
    printf("%d], ", w0.vec[i].coeffs[j]);

    polyz_pack(r0 + i * POLYZ_PACKEDBYTES, &w0.vec[i]);
  }
  printf("\n");
  return 0;
}

/*************************************************
 * Name:        crypto_sign_verify_and_Az_ct
 *
 * Description: Verifies signature.
 *
 * Arguments:   - uint8_t *m: pointer to input signature
 *              - size_t siglen: length of signature
 *              - const uint8_t *m: pointer to message
 *              - size_t mlen: length of message
 *              - const uint8_t *pk: pointer to bit-packed public key
 *
 * Returns 0 if signature could be verified correctly and -1 otherwise
 **************************************************/
int crypto_sign_verify_and_Az_ct(const uint8_t *sig, size_t siglen,
                                 const uint8_t *m, size_t mlen,
                                 const uint8_t *pk, polyveck *t0,
                                 int32_t *index) {
  unsigned int i, j;
  uint8_t buf[K * POLYW1_PACKEDBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t mu[CRHBYTES];
  uint8_t c[SEEDBYTES];
  uint8_t c2[SEEDBYTES];
  poly cp;
  polyvecl mat[K], z;
  polyveck t1, r1, r0, w1p, w1, h, t0hat;
  keccak_state state;
  int32_t poly_, coef_, diff;
  int8_t pm = 0;

  // We backup our w1 value for the exhaustive search on the k \times n
  // coefficients
  for (poly_ = 0; poly_ < K; poly_++) {
    for (coef_ = 0; coef_ < N; coef_++) {
      t0hat.vec[poly_].coeffs[coef_] = t0->vec[poly_].coeffs[coef_];
    }
  }

  if (siglen != CRYPTO_BYTES)
    return -1;

  unpack_pk(rho, &t1, pk);
  if (unpack_sig(c, &z, &h, sig))
    return -1;
  if (polyvecl_chknorm(&z, GAMMA1 - BETA))
    return -1;
  // printf("pas de pb\n");
  /* Compute CRH(H(rho, t1), msg) */
  shake256(mu, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_init(&state);
  shake256_absorb(&state, mu, SEEDBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(&cp, c);
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  poly_ntt(&cp);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  /* Computing Az - ct_1 2^d*/
  polyveck_sub(&w1p, &w1, &t1);
  polyveck_reduce(&w1p);
  polyveck_invntt_tomont(&w1p);
  polyveck_caddq(&w1p);
  polyveck_use_hint(&w1p, &w1p, &h);

  /* Computing Az - ct_1 2^d - ct_0 = Az - ct = Ay - cs_2*/
  polyveck_sub(&w1, &w1, &t1);
  polyveck_ntt(&t0hat);
  polyveck_pointwise_poly_montgomery(&t0hat, &cp, &t0hat);
  polyveck_sub(&w1, &w1, &t0hat);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);
  polyveck_caddq(&w1);
  polyveck_decompose(&r1, &r0, &w1);

  for (poly_ = 0; poly_ < K; poly_++) {
    for (coef_ = 0; coef_ < N; coef_++) {
      diff = w1p.vec[poly_].coeffs[coef_] - r1.vec[poly_].coeffs[coef_];
      if (diff != 0) {
        *index = poly_ * N + coef_;
        if (diff == 1) {
          pm = -2;
        } else if (diff == -1) {
          pm = -3;
        }
        return pm;
      }
    }
  }
  return -1;
}

/*************************************************
 * Name:        test_equality_c
 *
 * Description: Checks that two challenges of dilithium are the same.
 *
 * Arguments:   - uint8_t *c: first challenge
 *              - uint8_t *c: second challenge
 *
 * Returns 0 if the challenges are not equal and 1 if they are equal
 **************************************************/
int test_equality_c(uint8_t *c, uint8_t *c2) {
  for (uint8_t i = 0; i < SEEDBYTES; i++) {
    if (c[i] != c2[i]) {
      return 0;
    }
  }
  return 1;
}

/*************************************************
 * Name:        test_value_pm
 *
 * Description: Adds or subtracts 1 to value depending on flag neg
 *
 * Arguments:   - int32_t value: value to add or subtract 1
 *              - int32_t neg  : if the flag is set to 0 adds 1 else subtract 1
 *
 * Returns the value +/- 1 mod gamma_2
 **************************************************/
int32_t test_value_pm(int32_t value, int32_t neg) {

  if (value == 0) {
    if (neg == 1) {
      return value;
    }
  }
#if GAMMA2 == (Q - 1) / 32
  if (value == 15) {
    if (neg == 0) {
      return value;
    }
  }
#elif GAMMA2 == (Q - 1) / 88
  if (value == 43) {
    if (neg == 0) {
      return value;
    }
  }
#endif
  if (neg == 0) {
#if GAMMA2 == (Q - 1) / 32
    return (value + 1) & 15;
#elif GAMMA2 == (Q - 1) / 88
    if (value == 43) {
      return 0;
    } else {
      return value + 1;
    }
#endif
  } else {
#if GAMMA2 == (Q - 1) / 32
    return (value - 1) & 15;
#elif GAMMA2 == (Q - 1) / 88
    if (value == 0) {
      return 43;
    } else {
      return value - 1;
    }
#endif
  }
}
