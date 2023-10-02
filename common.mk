SHA3_ASM = $(wildcard sha3/*.s) $(wildcard sha3/$(SHA3_TARGET)/*.s)
SHA3_SRC = $(wildcard sha3/*.c) $(wildcard sha3/$(SHA3_TARGET)/*.c)

CC = gcc
CFLAGS = -Wall -pedantic -Wextra -O3
CPPFLAGS = -I. -Iutils -Ibatch_tools \
           -Isha3/$(SHA3_TARGET) -DUINTX_BITSIZE=$(UINTX_BITSIZE) \
           $(TEST_OPTIONS)

HDR = biscuit.h utils/utils.h batch_tools/batch_tools.h $(wildcard params*.h)
SRC = $(BISCUIT_FILE) utils/utils.c batch_tools/batch_tools.c
OBJ = $(SRC:.c=.o) $(SHA3_SRC:.c=.o) $(SHA3_ASM:.s=.o)

API_OBJ = nist/rng.o nist/api.o

EXE = nist/PQCgenKAT_sign test/test test/perf_api test/benchmark

all: $(EXE)

test/test: test/test.c $(OBJ)
test/benchmark: test/benchmark.c $(OBJ)

nist/PQCgenKAT_sign: LDLIBS = -lcrypto
nist/PQCgenKAT_sign: CPPFLAGS += -Inist
nist/PQCgenKAT_sign: nist/PQCgenKAT_sign.c $(API_OBJ) $(OBJ)

test/perf_api: LDLIBS = -lcrypto
test/perf_api: CPPFLAGS += -Inist
test/perf_api: test/perf_api.c $(API_OBJ) $(OBJ)

clean:
	rm -f $(API_OBJ) $(OBJ) $(EXE)
