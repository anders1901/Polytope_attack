//
//  PQCgenKAT_sign_Modified.c
//
//
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "additional_fct.h"
#include "nistkat/rng.h"
#include "sign.h"

#define MAX_MARKER_LEN 50

#define KAT_SUCCESS 0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR -3
#define KAT_CRYPTO_FAILURE -4

int main(int argc, char *argv[]) {
  char fn_req[48], fn_rsp[48];
  FILE *fp_req, *fp_rsp;
  uint8_t seed[48];
  uint8_t msg[3300];
  uint8_t entropy_input[48];
  uint8_t *m, *sm, *m1;
  size_t mlen, smlen, mlen1;
  int count;
  int done;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
  int ret_val, nb_KAT;
  char directory[48];

  if (argc != 2) {
    // No arguments, default behaviour as PQCgenKAT_sign.c with 100 tests
    nb_KAT = 100;
  } else {
    // If specified, use the number provided by the user for the number of tests
    nb_KAT = atoi(argv[1]);
  }

  struct stat st = {0};

  sprintf(directory, "../KAT/");
  if (stat(directory, &st) == -1) {
    mkdir(directory, 0700);
  }

  // Create the REQUEST file
  sprintf(fn_req, "../KAT/PQCsignKAT_%.16s.req", CRYPTO_ALGNAME);
  if ((fp_req = fopen(fn_req, "w")) == NULL) {
    printf("Couldn't open <%s> for write\n", fn_req);
    return KAT_FILE_OPEN_ERROR;
  }

  sprintf(fn_rsp, "../KAT/PQCsignKAT_%.16s.rsp", CRYPTO_ALGNAME);
  if ((fp_rsp = fopen(fn_rsp, "w")) == NULL) {
    printf("Couldn't open <%s> for write\n", fn_rsp);
    return KAT_FILE_OPEN_ERROR;
  }

  for (int i = 0; i < 48; i++)
    entropy_input[i] = i;

  randombytes_init(entropy_input, NULL, 256);
  for (int i = 0; i < nb_KAT; i++) {
    fprintf(fp_req, "count = %d\n", i);
    randombytes(seed, 48);
    fprintBstr(fp_req, "seed = ", seed, 48);
    mlen = 33 * (i + 1);
    fprintf(fp_req, "mlen = %lu\n", mlen);
    randombytes(msg, mlen);
    fprintBstr(fp_req, "msg = ", msg, mlen);
    fprintf(fp_req, "pk =\n");
    fprintf(fp_req, "sk =\n");
    fprintf(fp_req, "smlen =\n");
    fprintf(fp_req, "sm =\n\n");
  }
  fclose(fp_req);

  // Create the RESPONSE file based on what's in the REQUEST file
  if ((fp_req = fopen(fn_req, "r")) == NULL) {
    printf("Couldn't open <%s> for read\n", fn_req);
    return KAT_FILE_OPEN_ERROR;
  }

  fprintf(fp_rsp, "# %s\n\n", CRYPTO_ALGNAME);
  done = 0;
  do {
    if (FindMarker(fp_req, "count = "))
      fscanf(fp_req, "%d", &count);
    else {
      done = 1;
      break;
    }
    fprintf(fp_rsp, "count = %d\n", count);

    if (!ReadHex(fp_req, seed, 48, "seed = ")) {
      printf("ERROR: unable to read 'seed' from <%s>\n", fn_req);
      return KAT_DATA_ERROR;
    }
    fprintBstr(fp_rsp, "seed = ", seed, 48);

    randombytes_init(seed, NULL, 256);

    if (FindMarker(fp_req, "mlen = "))
      fscanf(fp_req, "%lu", &mlen);
    else {
      printf("ERROR: unable to read 'mlen' from <%s>\n", fn_req);
      return KAT_DATA_ERROR;
    }
    fprintf(fp_rsp, "mlen = %lu\n", mlen);

    m = (uint8_t *)calloc(mlen, sizeof(uint8_t));
    m1 = (uint8_t *)calloc(mlen + CRYPTO_BYTES, sizeof(uint8_t));
    sm = (uint8_t *)calloc(mlen + CRYPTO_BYTES, sizeof(uint8_t));

    if (!ReadHex(fp_req, m, (int)mlen, "msg = ")) {
      printf("ERROR: unable to read 'msg' from <%s>\n", fn_req);
      return KAT_DATA_ERROR;
    }
    fprintBstr(fp_rsp, "msg = ", m, mlen);

    // Generate the public/private keypair
    if ((ret_val = crypto_sign_keypair(pk, sk)) != 0) {
      printf("crypto_sign_keypair returned <%d>\n", ret_val);
      return KAT_CRYPTO_FAILURE;
    }
    fprintBstr(fp_rsp, "pk = ", pk, CRYPTO_PUBLICKEYBYTES);
    fprintBstr(fp_rsp, "sk = ", sk, CRYPTO_SECRETKEYBYTES);

    if ((ret_val = crypto_sign(sm, &smlen, m, mlen, NULL, 0, sk)) != 0) {
      printf("crypto_sign returned <%d>\n", ret_val);
      return KAT_CRYPTO_FAILURE;
    }

    fprintf(fp_rsp, "smlen = %lu\n", smlen);
    fprintBstr(fp_rsp, "sm = ", sm, smlen);
    fprintf(fp_rsp, "\n");

    if ((ret_val = crypto_sign_open(m1, &mlen1, sm, smlen, NULL, 0, pk)) != 0) {
      printf("crypto_sign_open returned <%d>\n", ret_val);
      return KAT_CRYPTO_FAILURE;
    }

    if (mlen != mlen1) {
      printf(
          "crypto_sign_open returned bad 'mlen': Got <%lu>, expected <%lu>\n",
          mlen1, mlen);
      return KAT_CRYPTO_FAILURE;
    }

    if (memcmp(m, m1, mlen)) {
      printf("crypto_sign_open returned bad 'm' value\n");
      return KAT_CRYPTO_FAILURE;
    }

    free(m);
    free(m1);
    free(sm);

  } while (!done);

  fclose(fp_req);
  fclose(fp_rsp);

  return KAT_SUCCESS;
}
