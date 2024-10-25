#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int FindMarker(FILE *infile, const char *marker);

int ReadHex(FILE *infile, unsigned char *a, int Length, char *str);

void fprintBstr(FILE *fp, char *s, unsigned char *a, unsigned long long l);

void fprintBstr2(FILE *fp, int b, char *s, unsigned char *a,
                 unsigned long long l);

void poly_2gamma2(poly *a);

void polyveck_2gamma2(polyveck *v);

unsigned int poly_make_hint_spec(poly *h, const poly *a0, const poly *a1);

unsigned int polyveck_make_hint_spec(polyveck *h, const polyveck *v0,
                                     const polyveck *v1);

#define crypto_sign_signature_spec DILITHIUM_NAMESPACE(signature_spec)
int crypto_sign_signature_spec(uint8_t *sig, 
                               size_t *siglen, 
                               const uint8_t *m,
                               size_t mlen, 
                               const uint8_t *ctx,
                               size_t ctxlen,
                               const uint8_t *sk);

#define crypto_sign_signature_spec_r0_norm_faulted                             \
  DILITHIUM_NAMESPACE(signature_spec_faulted)
int crypto_sign_signature_spec_r0_norm_faulted(uint8_t *sig, 
                                               size_t *siglen, 
                                               const uint8_t *m,
                                               size_t mlen, 
                                               const uint8_t *ctx,
                                               size_t ctxlen,
                                               const uint8_t *sk);

#define crypto_sign_signature_r0_norm_faulted                                  \
  DILITHIUM_NAMESPACE(signature_faulted)
int crypto_sign_signature_r0_norm_faulted(uint8_t *sig, size_t *siglen,
                                          const uint8_t *m, size_t mlen,
                                          const uint8_t *sk);

int test_coefficient_w1_different(const uint8_t *sig, size_t siglen,
                                  const uint8_t *m, size_t mlen,
                                  const uint8_t *pk, int32_t *index);

int compute_Az_minus_ct(const uint8_t *sig, size_t siglen, const uint8_t *m,
                        size_t mlen, const uint8_t *pk, polyveck *t0,
                        uint8_t *r1, uint8_t *r0);

int crypto_sign_verify_and_Az_ct(const uint8_t *sig, size_t siglen,
                                 const uint8_t *m, size_t mlen,
                                 const uint8_t *pk, polyveck *t0,
                                 int32_t *index);

int test_equality_c(uint8_t *c, uint8_t *c2);

int32_t test_value_pm(int32_t value, int32_t neg);