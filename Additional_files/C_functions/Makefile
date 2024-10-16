DILITHIUM_PATH = ../../dilithium-master/ref

CC ?= /usr/bin/cc
CFLAGS += -Wall -Wno-unused-variable\
  -Wshadow -Wvla -Wpointer-arith -O3 -fomit-frame-pointer -Wno-unused-result\
  -Wno-unused-parameter -Wno-unused-but-set-variable -I$(DILITHIUM_PATH)
SOURCES = sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c 
HEADERS = config.h params.h api.h sign.h packing.h polyvec.h poly.h ntt.h \
  reduce.h rounding.h symmetric.h randombytes.h
KECCAK_SOURCES = $(SOURCES) fips202.c symmetric-shake.c randombytes.c
KECCAK_HEADERS = $(HEADERS) fips202.h randombytes.h

KAT_SOURCES = $(SOURCES) fips202.c symmetric-shake.c rng.c
KAT_HEADERS = $(HEADERS) fips202.h rng.h

ALL_KAT_SOURCES = $(patsubst %,$(DILITHIUM_PATH)/%,$(KAT_SOURCES)) additional_fct.c
ALL_KAT_HEADERS = $(patsubst %,$(DILITHIUM_PATH)/%,$(KAT_HEADERS)) additional_fct.h

ALL_SOURCES = $(patsubst %,$(DILITHIUM_PATH)/%,$(KECCAK_SOURCES)) additional_fct.c
ALL_HEADERS = $(patsubst %,$(DILITHIUM_PATH)/%,$(KECCAK_HEADERS)) additional_fct.h

# START Files added
PQCgenKAT_sign_Modified2: PQCgenKAT_sign_Modified.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto

PQCgenKAT_sign_Modified3: PQCgenKAT_sign_Modified.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto

PQCgenKAT_sign_Modified5: PQCgenKAT_sign_Modified.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto

Gen_Signs_KeyKAT2: Gen_Signs_KeyKAT.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto

Gen_Signs_KeyKAT3: Gen_Signs_KeyKAT.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto

Gen_Signs_KeyKAT5: Gen_Signs_KeyKAT.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto

Gen_SignsRef_KeyKAT2: Gen_SignsRef_KeyKAT.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto

Gen_SignsRef_KeyKAT3: Gen_SignsRef_KeyKAT.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto

Gen_SignsRef_KeyKAT5: Gen_SignsRef_KeyKAT.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto

Filter_Signs_Proposition32: Filter_Signs_Proposition3.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto

Filter_Signs_Proposition33: Filter_Signs_Proposition3.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto

Filter_Signs_Proposition35: Filter_Signs_Proposition3.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto

Filter_Signs_Proposition52: Filter_Signs_Proposition5.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto

Filter_Signs_Proposition53: Filter_Signs_Proposition5.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto

Filter_Signs_Proposition55: Filter_Signs_Proposition5.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto

Verify_Assumption22: Verify_Assumption2.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto

Verify_Assumption23: Verify_Assumption2.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto

Verify_Assumption25: Verify_Assumption2.c $(ALL_KAT_SOURCES) $(ALL_KAT_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 -o $@ $< $(ALL_KAT_SOURCES) $(LDFLAGS) -lcrypto
# END Files added

clean:
	rm -f PQCgenKAT_sign_Modified2 PQCgenKAT_sign_Modified3 PQCgenKAT_sign_Modified5 \
	      Gen_Signs_KeyKAT2 Gen_Signs_KeyKAT3 Gen_Signs_KeyKAT5 \
		  Gen_SignsRef_KeyKAT2 Gen_SignsRef_KeyKAT3 Gen_SignsRef_KeyKAT5 \
		  Filter_Signs_Proposition32 Filter_Signs_Proposition33 Filter_Signs_Proposition35 \
		  Filter_Signs_Proposition52 Filter_Signs_Proposition53 Filter_Signs_Proposition55 \
		  Verify_Assumption22 Verify_Assumption23 Verify_Assumption25

format:
	clang-format-15 -i *.[ch]

.PHONY: clean format


