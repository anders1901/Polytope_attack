//
//  Filter_Signs_Proposition3.c
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
#include "packing.h"
#include "nistkat/rng.h"
#include "sign.h"

#define MAX_MARKER_LEN 50
#define MSG_LEN 32

#define SUCCESS 0
#define FILE_OPEN_ERROR -1
#define DATA_ERROR -3
#define CRYPTO_FAILURE -4

int main(int argc, char *argv[]) {
  char fn_rsp[48], fn_signs[64], fn_signs_filtered[96];
  FILE *fp_rsp, *fp_signs, *fp_signs_filtered;
  uint8_t seed[48];
  uint8_t entropy_input[48];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sm[4 * 3300];
  size_t smlen;
  int ret_val, done, done_keys, done_signs, count, count_signs;
  int32_t verification_code, coefficient_code, index;
  int16_t i, j, mlen;
  uint8_t msg[4 * MSG_LEN];
  uint32_t nb_Signs, count_filtered_signs;
  char directory[48];
  long iter = 0;
  struct stat st = {0};
  // polyveck            t0;
  uint8_t r1[K * POLYW1_PACKEDBYTES], r0[K * POLYZ_PACKEDBYTES];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0;
  uint8_t rho[SEEDBYTES], tr[SEEDBYTES], key[SEEDBYTES];

  if (argc != 2) {
    // Default number of signatures collected
    nb_Signs = 1250000;
  } else {
    nb_Signs = atoi(argv[1]);
  }

  // Basic entropy input, the same as for the KAT file
  for (j = 0; j < 48; j++) {
    entropy_input[j] = j;
  }

  // We test if the directory "Signs/" exists, if not we create it
  sprintf(directory, "../Signs/");
  if (stat(directory, &st) == -1) {
    mkdir(directory, 0700);
  }

  // We test if the directory "Signs/Dilithium{VERSION}" exists, if not we
  // create it
  sprintf(directory, "../Signs/%.16s/", CRYPTO_ALGNAME);
  if (stat(directory, &st) == -1) {
    mkdir(directory, 0700);
  }

  // We test if the directory "signs_filtered/" exists, if not we create it
  sprintf(directory, "../Signs_filtered/");
  if (stat(directory, &st) == -1) {
    mkdir(directory, 0700);
  }

  // We test if the directory "signs_filtered/Dilithium{VERSION}/" exists, if
  // not we create it
  sprintf(directory, "../Signs_filtered/%.16s/", CRYPTO_ALGNAME);
  if (stat(directory, &st) == -1) {
    mkdir(directory, 0700);
  }

  // We open the KAT file with the number of keys targeted
  sprintf(fn_rsp, "../KAT/PQCsignKAT_%.16s.rsp", CRYPTO_ALGNAME);
  if ((fp_rsp = fopen(fn_rsp, "r")) == NULL) {
    printf("Couldn't open <%s> for read\n", fn_rsp);
    return FILE_OPEN_ERROR;
  }

  // Here we iterate through all the keys in the KAT file
  done = 0;
  do {
    randombytes_init(entropy_input, NULL, 256);
    if (FindMarker(fp_rsp, "count = ")) {
      fscanf(fp_rsp, "%d", &count);
    } else {
      done = 1;
      break;
    }

    count_filtered_signs = 0;
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

    // printf(">>> Test avant\n");
    unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);
    // printf(">>> Test après\n");

    // We open the file with the nb_Signs faulted signatures associated to the
    // key count of the KAT file
    sprintf(fn_signs, "../Signs/%.16s/%dSignsKAT_key%d.rsp", CRYPTO_ALGNAME,
            nb_Signs, count);
    if ((fp_signs = fopen(fn_signs, "r")) == NULL) {
      printf("Couldn't open <%s> for read\n", fn_signs);
      return FILE_OPEN_ERROR;
    }

    // We create the file with the nb_Signs USEFUL faulted signatures
    // associated to the key count of the KAT file
    sprintf(fn_signs_filtered,
            "../Signs_filtered/%.16s/%dSignsKAT_key%d_filtered.rsp",
            CRYPTO_ALGNAME, nb_Signs, count);
    if ((fp_signs_filtered = fopen(fn_signs_filtered, "w")) == NULL) {
      printf("Couldn't open <%s> for write\n", fn_signs_filtered);
      return FILE_OPEN_ERROR;
    }

    // Here we iterate through all the signatures in the Signs file for the key
    // targeted
    done_signs = 0;
    do {
      if (FindMarker(fp_signs, "count = ")) {
        fscanf(fp_signs, "%d", &count_signs);
      } else {
        done_signs = 1;
        break;
      }
      if (!ReadHex(fp_signs, sm, (int)CRYPTO_BYTES, "sm = ")) {
        printf("ERROR: unable to read 'sm' from <%s>\n", fn_signs);
        return DATA_ERROR;
      }

      if (!ReadHex(fp_signs, msg, (int)MSG_LEN, "msg = ")) {
        printf("ERROR: unable to read 'msg' from <%s>\n", fn_signs);
        return DATA_ERROR;
      }

      coefficient_code = crypto_sign_verify_and_Az_ct(sm, CRYPTO_BYTES, msg,
                                                      MSG_LEN, NULL, 0, pk, &t0, &index);
      // printf("coefficient_code = %d\n", coefficient_code);
      if (coefficient_code < -1) {
        fprintf(fp_signs_filtered, "count = %u\n", count_filtered_signs);
        fprintBstr(fp_signs_filtered, "sm = ", sm, CRYPTO_BYTES);
        fprintBstr(fp_signs_filtered, "msg = ", msg, MSG_LEN);
        fprintf(fp_signs_filtered, "neg = %d\n", coefficient_code + 3);
        fprintf(fp_signs_filtered, "index = %d\n", index);
        fprintf(fp_signs_filtered, "\n");

        if (count_signs % 500 == 0) {
          printf("%d/%d/%d\r", count_filtered_signs, count_signs, nb_Signs);
          fflush(stdout);
        }
        count_filtered_signs++;
      }

      // if (count_signs == 64){
      //  done_signs = 1;
      // }
    } while (!done_signs);
    fclose(fp_signs);
    fclose(fp_signs_filtered);
  } while (!done);
  fclose(fp_rsp);

  return SUCCESS;
}