#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "params.h"
#include "polyvec.h"
#include "poly.h"


int	FindMarker(FILE *infile, const char *marker);
int	ReadHex(FILE *infile, unsigned char *a, int Length, char *str);
void	fprintBstr(FILE *fp, char *s, unsigned char *a, unsigned long long l);

void poly_2gamma2(poly *a);

void polyveck_2gamma2(polyveck *v) ;

unsigned int poly_make_hint_spec(poly *h, const poly *a0, const poly *a1);

unsigned int polyveck_make_hint_spec(polyveck *h,
                                const polyveck *v0,
                                const polyveck *v1);

#define crypto_sign_signature_spec DILITHIUM_NAMESPACE(signature_spec)
int crypto_sign_signature_spec(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *sk);

#define crypto_sign_signature_spec_r0_norm_faulted DILITHIUM_NAMESPACE(signature_spec_faulted)
int crypto_sign_signature_spec_r0_norm_faulted(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *sk);

#define crypto_sign_signature_r0_norm_faulted DILITHIUM_NAMESPACE(signature_faulted)
int crypto_sign_signature_r0_norm_faulted(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *sk);

int test_coefficient_w1_different(const uint8_t *sig,
                       size_t siglen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *pk,
                       int32_t * index);

#define crypto_sign_filter DILITHIUM_NAMESPACE(filter)
void crypto_sign_filter(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *sk,
                          const uint8_t *pk,
                          uint64_t *w0_to_0_detected_filter,
                          uint64_t *w0_to_0_total,
                          uint64_t *values_detected_filter);
