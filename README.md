# Lattice-based digital signature scheme **qTESLA**

## Jay
The test for measuring the time of key generation/the time of sign json plaintext/the time of sign open the json plaintext/length of cipher message is added. And I also add the template test file which will copy to each signature scheme for implementating test cases easly.

## Original
This is the software package of the post-quantum lattice-based digital signature
scheme **qTESLA** for the NIST Post-Quantum Cryptography Standardization project. 

**qTESLA** is a family of post-quantum signature schemes based on the hardness of the decisional
Ring Learning With Errors (R-LWE) problem. 
The scheme is an efficient variant of the Bai-Galbraith signature scheme, which in
turn is based on the "Fiat-Shamir with Aborts" framework by Lyubashevsky, adapted
to the setting of ideal lattices.

**qTESLA** utilizes two different approaches for parameter generation in order to target a wide
range of application scenarios. The first approach, referred to as "heuristic qTESLA",
follows a heuristic parameter generation. The second approach, referred to as "provably-
secure qTESLA", follows a provably-secure parameter generation according to existing security
reductions.

Concretely, **qTESLA** includes five parameter sets targeting two security levels:

I  Heuristic qTESLA:

* qTESLA-I: NIST's security category 1.
* qTESLA-III-speed: NIST's security category 3 (optimized for speed).
* qTESLA-III-size: NIST's security category 3 (optimized for size).

II  Provably-secure qTESLA:

* qTESLA-p-I: NIST's security category 1.
* qTESLA-p-III: NIST's security category 3.

The full specification of the scheme can be found in the qTESLA [`website`](http://qtesla.org).

## Contents

- [`KAT`](KAT/)                     : Contains the Known Answer Tests
- [`Reference_implementation`](Reference_Implementation) : Contains the reference implementations
- [`Additional_implementations/avx2`](AVX2_Implementation) : Contains the AVX2-optimized implementations

## Contents of subfolders

### Subfolder `KAT`:
This folder contains known answer test results for the proposed parameter sets, 
classified by platform support (xx = 32 or 64 bits) and implementation (reference or AVX2).

- `ref/<KATxx>/PQCsignKAT_qTesla-I.rsp` : Known answer test results for qTesla-I
- `ref/<KATxx>/PQCsignKAT_qTesla-III-size.rsp` : Known answer test results for qTesla-III-size
- `ref/<KATxx>/PQCsignKAT_qTesla-III-speed.rsp` : Known answer test results for qTesla-III-speed
- `ref/<KATxx>/PQCsignKAT_qTesla-p-I.rsp`: Known answer test results for qTesla-p-I
- `ref/<KATxx>/PQCsignKAT_qTesla-p-III.rsp` : Known answer test results for qTesla-p-III
- `avx2/<KATxx>/PQCsignKAT_qTesla-I.rsp` : Known answer test results for qTesla-I
- `avx2/<KATxx>/PQCsignKAT_qTesla-III-size.rsp` : Known answer test results for qTesla-III-size
- `avx2/<KATxx>/PQCsignKAT_qTesla-III-speed.rsp` : Known answer test results for qTesla-III-speed

### Subfolder `Reference_Implementation`:
This folder contains five subfolders which contain the reference implementations
for the proposed parameter sets:

- "qTesla-I" : Reference implementation of qTesla-I with parameters for
               NIST’s security category 1
- "qTesla-III-size" : Reference implementation of qTesla-III-size with parameters for
               NIST’s security category 3
- "qTesla-III-speed" : Reference implementation of qTesla-III-speed with parameters for
               NIST’s security category 3
- "qTesla-p-I" : Reference implementation of qTesla-p-I with parameters for
               NIST’s security category 1
- "qTesla-p-III" : Reference implementation of qTesla-p-III with parameters for
               NIST’s security category 3

### Subfolder `Additional_Implementations/avx2`:
This folder contains three subfolders which contain the additional AVX2 implementations
for the heuristic parameter sets:

- "qTesla-I" : AVX2 implementation of qTesla-I with parameters for
               NIST’s security category 1
- "qTesla-III-size" : AVX2 implementation of qTesla-III-size with parameters for
               NIST’s security category 3
- "qTesla-III-speed" : AVX2 implementation of qTesla-III-speed with parameters for
               NIST’s security category 3

## Instructions for Linux

Each implementation directory has its own makefile, and can be compiled by executing,
for the reference implementations:

```sh
$ cd Reference_implementation/qTesla_{SET}
$ make ARCH=[x64/x86/ARM/ARM64] CC=[gcc/clang] DEBUG=[TRUE/FALSE]
```

For the AVX2 implementations: 

```sh
$ cd Additional_implementations/avx2/qTesla_{SET}
$ make CC=[gcc/clang] DEBUG=[TRUE/FALSE]
```

By default (i.e., just running "make"), the compilation is done with gcc for x64, 
DEBUG=FALSE. Testing and benchmarking results can be seen by running the command:

```sh
$ ./test_qtesla-{SET}
```
where {SET} is one of the parameter set options I, III-speed, III-size, p-I or p-III.

This outputs key and signature sizes, and cycle counts for key generation, signing,
and verification.

If compilation is done with DEBUG=TRUE, executing test_qtesla-{SET} additionally 
outputs acceptance probabilities during key generation and signing.

KAT files can be generated by executing:

```sh
./PQCgenKAT_sign-{SET}
```

Precomputed KAT values can be tested against the code by executing:

```sh
./PQCtestKAT_sign-{SET}
```

## License

This software is licensed under the MIT License; see [`License`](LICENSE) for details.
The software also includes third-party code licensed as follows:

- `src/sha3/fips202.c`: public domain
- `src/sha3/fips202x4.c`: public domain
- `src/sha3/keccak4x`: all files in this folder are public domain  ([CC0](http://creativecommons.org/publicdomain/zero/1.0/)), excepting
- `src/sha3/keccak4x/brg_endian.h` which is copyrighted by Brian Gladman and comes with a BSD 3-clause license.
- `tests/PQCtestKAT_sign.c`: copyrighted by Lawrence E. Bassham 
- `tests/rng.c`: copyrighted by Lawrence E. Bassham

## The qTESLA team

The qTESLA team is integrated by the following researchers from industry and academia
(in alphabetical order):

- Sedat Akleylek, Ondokuz Mayis University, Turkey
- Erdem Alkim, Ondokuz Mayis University, Turkey
- Paulo S. L. M. Barreto, University of Washington Tacoma, USA
- Nina Bindel, Technische Universität Darmstadt, Germany
- Johannes Buchmann, Technische Universität Darmstadt, Germany
- Edward Eaton, ISARA Corporation, Canada
- Gus Gutoski, ISARA Corporation, Canada
- Juliane Krämer, Technische Universität Darmstadt, Germany
- Patrick Longa, Microsoft Research, USA
- Harun Polat, Technische Universität Darmstadt, Germany
- Jefferson E. Ricardini, University of São Paulo, Brazil
- Gustavo Zanon, University of São Paulo, Brazil
