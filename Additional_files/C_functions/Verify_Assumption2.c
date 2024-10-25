//
//  Verify_Assumption2.c
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
#define MSG_LEN 32

#define SUCCESS 0
#define FILE_OPEN_ERROR -1
#define DATA_ERROR -3
#define CRYPTO_FAILURE -4

int main(int argc, char *argv[]) {
  char fn_rsp[32], fn_signs[64];
  FILE *fp_rsp, *fp_signs;
  uint8_t seed[48];
  uint8_t entropy_input[48];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sm[4 * 3300];
  size_t smlen;
  int ret_val, done, count;
  int16_t i, j, mlen;
  uint8_t msg[4 * MSG_LEN];
  uint32_t nb_Signs;
  char directory[32];
  long iter = 0;

  if (argc != 2) {
    // Default number of signatures collected
    nb_Signs = 1250000;
  } else {
    nb_Signs = atoi(argv[1]);
  }

  // Basic entropy input, the same as for the KAT file
  for (j = 0; j < 48; j++) {
    entropy_input[j] = 1;
  }

  sprintf(fn_rsp, "PQCsignKAT_%.16s.rsp", CRYPTO_ALGNAME);
  if ((fp_rsp = fopen(fn_rsp, "r")) == NULL) {
    printf("Couldn't open <%s> for read\n", fn_rsp);
    return FILE_OPEN_ERROR;
  }

  done = 0;
  do {
    randombytes_init(entropy_input, NULL, 256);
    if (FindMarker(fp_rsp, "count = ")) {
      fscanf(fp_rsp, "%d", &count);
    } else {
      done = 1;
      break;
    }

    if (!ReadHex(fp_rsp, seed, 48, "seed = ")) {
      printf("ERROR: unable to read 'seed' from <%s>\n", fn_rsp);
      return DATA_ERROR;
    }

    if (!ReadHex(fp_rsp, pk, (int)CRYPTO_PUBLICKEYBYTES, "pk = ")) {
      printf("ERROR: unable to read 'pk' from <%s>\n", fn_rsp);
      return DATA_ERROR;
    }

    if (!ReadHex(fp_rsp, sk, (int)CRYPTO_SECRETKEYBYTES, "sk = ")) {
      printf("ERROR: unable to read 'sk' from <%s>\n", fn_rsp);
      return DATA_ERROR;
    }

    for (uint32_t nb_signs = 0; nb_signs < nb_Signs; nb_signs++) {
      randombytes(msg, MSG_LEN);

      if ((ret_val = crypto_sign_signature_r0_norm_faulted(sm, &smlen, msg,
                                                           MSG_LEN, NULL, 0, sk)) != 0) {
        printf("crypto_sign returned <%d>\n", ret_val);
        return CRYPTO_FAILURE;
      }

      if ((ret_val = crypto_sign_verify(sm, smlen, msg, MSG_LEN, NULL, 0, pk)) != 0) {
        printf("crypto_sign returned <%d>\n", ret_val);
        return CRYPTO_FAILURE;
      }

      if (nb_signs % 5000 == 0) {
        printf("%d faulted signatures verified over the %d tested\r", nb_signs,
               nb_Signs);
        fflush(stdout);
      }
    }

  } while (!done);
  fclose(fp_rsp);

  return SUCCESS;
}
