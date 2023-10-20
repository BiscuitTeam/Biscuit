# Biscuit
Biscuit: Shorter MPC-based Signature from PoSSo

```
.
├── Makefile            # Makefile to build the programs
├── common.mk
├── params_mpcith.h     # Parameters for MPCitH protocol
├── params_posso.h      # Parameters for PoSSo problem
├── params_biscuit.h    # Parameters for biscuit
├── params_instance.h   # Parameters not already fixed in previous files
├── params.h            # File to be included for fixed instance implementation
├── utils/              # Hash functions and seed derivation
│   ├── utils.h
│   └── utils.c
├── batch_tools/        # Functions for dealing with vectors of Fq elements
│   ├── batch_tools.h
│   ├── batch_tools.c
│   └── mul_gf2_*.inc
├── biscuit.h           # main header
├── biscuit.c           # main file
├── nist/               # NIST package (rng and api)
│   ├── rng.h
│   ├── rng.c
│   ├── api.h
│   ├── api.c
│   └── PQCgenKAT_sign.c
├── test/
│   ├── test.c          # Basic test file for the biscuit functions
│   ├── benchmark.c     # File to benchmark internal some parameters
│   └── perf_api.c      # Run a single perf test on NIST APIs
└── sha3/               # Directory containing SHA3 implementation from XKCP
```
The SHA3 implementation comes from the [XKCP Project](https://github.com/XKCP/XKCP)

The Makefile allows to compile the following targets:
- `test/PQCgenKAT_sign`: program to generate known answer tests
- `test/test`: program to test keygen, sign and verify. Check that the
  verification of a valid signature is valid.
- `test/benchmark`: program to benchmark the inner function
  `keygen`, `sign`, `verify`.
- `test/perf_api`: program to benchmark the performances of the
  `crypto_sign_keypair`, `crypto_sign`, `crypto_sign_open` APIs

The values in `test/perf_api.c` and `test/benchmark.c` are obtained by counting
`PERF_HW_COUNT_CPU_CYCLES`. This will work only on linux operating system.

Example:
```
> make test/benchmark
> ./test/benchmark lambda=128 tau=34 N=16 q=16 n=64 m=67 d=2
Run 100 tests for each function and take the mean number of cycles
================================================================================
params: lambda=128, tau=34, N=16, q=16, n=64, m=67, d=2
sizes: sk=115 bytes, pk=50 bytes, sig=6726 bytes
keygen: 84737.930000 cycles
sign: 9572124.810000 cycles
verif (ok): 8723494.620000 cycles
```

# Parameters cookbook
The parameters can be changed/moved in the `params_*.h` files.

To have an implementation that supports only fixed parameters
(e.g. only biscuit128f):
 - set `SEC_LEVEL`, `NB_ITERATIONS`, `NB_PARTIES`
   in `params_mpcith.h`
 - set `FIELD_SIZE`, `DEGREE`, `NB_VARIABLES`, `NB_EQUATIONS`
   in `params_posso.h`

To have an implementation that supports only one flavour (small/fast)
but all security levels (e.g. only biscuit128s, biscuit192s, biscuit256s):
 - set `NB_PARTIES`
   in `params_mpcith.h`
 - set `FIELD_SIZE`, `DEGREE`
   in `params_posso.h`

To have an implementation that supports only one security level, but
all flavours: (e.g. only biscuit128s, biscuit128f):
 - set `SEC_LEVEL`
   in `params_mpcith.h`
 - set `FIELD_SIZE`, `DEGREE`, `NB_VARIABLES`, `NB_EQUATIONS`
   in `params_posso.h`

To have an implementation that supports all biscuit specified variants:
 - set **nothing**
   in `params_mpcith.h`
 - set `FIELD_SIZE`, `DEGREE`
   in `params_posso.h`

Note that for specified instances of `biscuit`, `FIELD_SIZE=16` and `DEGREE=2`.

To have an implementation that supports all biscuit variants included ones
that are not specified:
 - set **nothing**
   in `params_mpcith.h`
 - set **nothing**
   in `params_posso.h`

For the parameters that are not specified in `params_mpcith.h` or
`params_posso.h`, they can be set in `params_instance.h` to properly
compile run `test/test` and `test/perf_api`.
