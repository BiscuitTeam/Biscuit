#define _GNU_SOURCE
#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <inttypes.h>
#include <sys/types.h>

#include <time.h>

#include "perf.h"

#include "api.h"
#include "rng.h"

#define MSGBYTES 32

int
main (void)
{
  long long count;

  int status;
  unsigned char *pk, *sk, *msg, *m, *sm;
  unsigned long long mlen, smlen;
  unsigned char entropy_input[48] = { 0 };

  INIT_PERF ();

  pk = malloc (CRYPTO_PUBLICKEYBYTES);
  sk = malloc (CRYPTO_SECRETKEYBYTES);
  m = malloc (MSGBYTES);
  sm = malloc (CRYPTO_BYTES + MSGBYTES);
  msg = malloc (MSGBYTES);

  srand (time (NULL));
  entropy_input[0] = (unsigned char) rand ();
  randombytes_init (entropy_input, NULL, 128);

  for (int i = 0; i < MSGBYTES; i++)
    msg[i] = i;

  PERF (crypto_sign_keypair (pk, sk), &count);
  printf ("sign_keypair: %lld cycles\n", count);
  printf ("pk: %d bytes\n", CRYPTO_PUBLICKEYBYTES);
  printf ("sk: %d bytes\n", CRYPTO_SECRETKEYBYTES);

  PERF (crypto_sign (sm, &smlen, msg, MSGBYTES, sk), &count);
  printf ("sign: %lld cycles\n", count);
  printf ("sig: %d bytes\n", CRYPTO_BYTES);

  PERF (status = crypto_sign_open (m, &mlen, sm, smlen, pk), &count);
  printf ("sign_open: %lld cycles\n", count);
  printf ("status: %s\n", status == 0 ? "OK" : "KO");

  free (pk);
  free (sk);
  free (m);
  free (sm);
  free (msg);

  return status;
}
