# Argon2

[![Build Status](https://travis-ci.org/P-H-C/phc-winner-argon2.svg?branch=master)](https://travis-ci.org/P-H-C/phc-winner-argon2)
[![Build status](https://ci.appveyor.com/api/projects/status/8nfwuwq55sgfkele?svg=true)](https://ci.appveyor.com/project/P-H-C/phc-winner-argon2)
[![codecov.io](https://codecov.io/github/P-H-C/phc-winner-argon2/coverage.svg?branch=master)](https://codecov.io/github/P-H-C/phc-winner-argon2?branch=master)

This is the reference C implementation of Argon2, the password-hashing
function that won the [Password Hashing Competition
(PHC)](https://password-hashing.net). This is also modified for use with 
CMake's Fetch Content

Argon2 is a password-hashing function that summarizes the state of the
art in the design of memory-hard functions and can be used to hash
passwords for credential storage, key derivation, or other applications.

It has a simple design aimed at the highest memory filling rate and
effective use of multiple computing units, while still providing defense
against tradeoff attacks (by exploiting the cache and memory organization
of the recent processors).

Argon2 has three variants: Argon2i, Argon2d, and Argon2id. Argon2d is faster
and uses data-depending memory access, which makes it highly resistant
against GPU cracking attacks and suitable for applications with no threats
from side-channel timing attacks (eg. cryptocurrencies). Argon2i instead
uses data-independent memory access, which is preferred for password
hashing and password-based key derivation, but it is slower as it makes
more passes over the memory to protect from tradeoff attacks. Argon2id is a
hybrid of Argon2i and Argon2d, using a combination of data-depending and
data-independent memory accesses, which gives some of Argon2i's resistance to
side-channel cache timing attacks and much of Argon2d's resistance to GPU
cracking attacks.

Argon2i, Argon2d, and Argon2id are parametrized by:

* A **time** cost, which defines the amount of computation realized and
  therefore the execution time, given in number of iterations
* A **memory** cost, which defines the memory usage, given in kibibytes
* A **parallelism** degree, which defines the number of parallel threads

The [Argon2 document](argon2-specs.pdf) gives detailed specs and design
rationale.

Please report bugs as issues on this repository.

## Usage

`cmake` builds the static library `libargon2.a`.
Tests are currently not implemented.

### Library

`libargon2` provides an API to both low-level and high-level functions
for using Argon2.

The example program below hashes the string "password" with Argon2i
using the high-level API and then using the low-level API. While the
high-level API takes the three cost parameters (time, memory, and
parallelism), the password input buffer, the salt input buffer, and the
output buffers, the low-level API takes in these and additional parameters
, as defined in [`include/argon2.h`](include/argon2.h).

There are many additional parameters, but we will highlight three of them here.

1. The `secret` parameter, which is used for [keyed hashing](
   https://en.wikipedia.org/wiki/Hash-based_message_authentication_code).
   This allows a secret key to be input at hashing time (from some external
   location) and be folded into the value of the hash. This means that even if
   your salts and hashes are compromized, an attacker cannot brute-force to find
   the password without the key.

2. The `ad` parameter, which is used to fold any additional data into the hash
   value. Functionally, this behaves almost exactly like the `secret` or `salt`
   parameters; the `ad` parameter is folding into the value of the hash.
   However, this parameter is used for different data. The `salt` should be a
   random string stored alongside your password. The `secret` should be a random
   key only usable at hashing time. The `ad` is for any other data.

3. The `flags` parameter, which determines which memory should be securely
   erased. This is useful if you want to securly delete the `pwd` or `secret`
   fields right after they are used. To do this set `flags` to either
   `ARGON2_FLAG_CLEAR_PASSWORD` or `ARGON2_FLAG_CLEAR_SECRET`. To change how
   internal memory is cleared, change the global flag
   `FLAG_clear_internal_memory` (defaults to clearing internal memory).

Here the time cost `t_cost` is set to 2 iterations, the
memory cost `m_cost` is set to 2<sup>16</sup> kibibytes (64 mebibytes),
and parallelism is set to 1 (single-thread).

Compile for example as `gcc test.c libargon2.a -Isrc -o test`, if the program
below is named `test.c` and placed in the project's root directory.

```c
#include "argon2.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define HASHLEN 32
#define SALTLEN 16
#define PWD "password"

int main(void)
{
    uint8_t hash1[HASHLEN];
    uint8_t hash2[HASHLEN];

    uint8_t salt[SALTLEN];
    memset( salt, 0x00, SALTLEN );

    uint8_t *pwd = (uint8_t *)strdup(PWD);
    uint32_t pwdlen = strlen((char *)pwd);

    uint32_t t_cost = 2;            // 2-pass computation
    uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
    uint32_t parallelism = 1;       // number of threads and lanes

    // high-level API
    argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash1, HASHLEN);

    // low-level API
    argon2_context context = {
        hash2,  /* output array, at least HASHLEN in size */
        HASHLEN, /* digest length */
        pwd, /* password array */
        pwdlen, /* password length */
        salt,  /* salt array */
        SALTLEN, /* salt length */
        NULL, 0, /* optional secret data */
        NULL, 0, /* optional associated data */
        t_cost, m_cost, parallelism, parallelism,
        ARGON2_VERSION_13, /* algorithm version */
        NULL, NULL, /* custom memory allocation / deallocation functions */
        /* by default only internal memory is cleared (pwd is not wiped) */
        ARGON2_DEFAULT_FLAGS
    };

    int rc = argon2i_ctx( &context );
    if(ARGON2_OK != rc) {
        printf("Error: %s\n", argon2_error_message(rc));
        exit(1);
    }
    free(pwd);

    for( int i=0; i<HASHLEN; ++i ) printf( "%02x", hash1[i] ); printf( "\n" );
    if (memcmp(hash1, hash2, HASHLEN)) {
        for( int i=0; i<HASHLEN; ++i ) {
            printf( "%02x", hash2[i] );
        }
        printf("\nfail\n");
    }
    else printf("ok\n");
    return 0;
}
```

To use Argon2d instead of Argon2i call `argon2d_hash_raw` instead of
`argon2i_hash_raw` using the high-level API, and `argon2d` instead of
`argon2i` using the low-level API. Similarly for Argon2id, call `argon2id_hash_raw`
and `argon2id`.

To produce the crypt-like encoding rather than the raw hash, call
`argon2i_hash_encoded` for Argon2i, `argon2d_hash_encoded` for Argon2d, and
`argon2id_hash_encoded` for Argon2id

See [`include/argon2.h`](include/argon2.h) for API details.

*Note: in this example the salt is set to the all-`0x00` string for the
sake of simplicity, but in your application you should use a random salt.*

## Bindings

Bindings are available for the following languages (make sure to read
their documentation):

* [Android (Java/Kotlin)](https://github.com/lambdapioneer/argon2kt) by [@lambdapioneer](https://github.com/lambdapioneer)
* [Dart](https://github.com/tmthecoder/dargon2) by [@tmthecoder](https://github.com/tmthecoder)
* [Elixir](https://github.com/riverrun/argon2_elixir) by [@riverrun](https://github.com/riverrun)
* [Erlang](https://github.com/ergenius/eargon2) by [@ergenius](https://github.com/ergenius)
* [Go](https://github.com/tvdburgt/go-argon2) by [@tvdburgt](https://github.com/tvdburgt)
* [Haskell](https://hackage.haskell.org/package/argon2) by [@hvr](https://github.com/hvr)
* [JavaScript (native)](https://github.com/ranisalt/node-argon2), by [@ranisalt](https://github.com/ranisalt)
* [JavaScript (native)](https://github.com/jdconley/argon2themax), by [@jdconley](https://github.com/jdconley)
* [JavaScript (ffi)](https://github.com/cjlarose/argon2-ffi), by [@cjlarose](https://github.com/cjlarose)
* [JavaScript (browser)](https://github.com/antelle/argon2-browser), by [@antelle](https://github.com/antelle)
* [JVM](https://github.com/phxql/argon2-jvm) by [@phXql](https://github.com/phxql)
* [JVM (with keyed hashing)](https://github.com/kosprov/jargon2-api) by [@kosprov](https://github.com/kosprov)
* [Lua (native)](https://github.com/thibaultCha/lua-argon2) by [@thibaultCha](https://github.com/thibaultCha)
* [Lua (ffi)](https://github.com/thibaultCha/lua-argon2-ffi) by [@thibaultCha](https://github.com/thibaultCha)
* [OCaml](https://github.com/Khady/ocaml-argon2) by [@Khady](https://github.com/Khady)
* [Python (native)](https://pypi.python.org/pypi/argon2), by [@flamewow](https://github.com/flamewow)
* [Python (ffi)](https://pypi.python.org/pypi/argon2_cffi), by [@hynek](https://github.com/hynek)
* [Python (ffi, with keyed hashing)](https://github.com/thusoy/porridge), by [@thusoy](https://github.com/thusoy)
* [Python (ffi, with keyed hashing)](https://github.com/ultrahorizon/pyargon2), by [@ultrahorizon](https://github.com/ultrahorizon)
* [R](https://cran.r-project.org/package=argon2) by [@wrathematics](https://github.com/wrathematics)
* [Ruby](https://github.com/technion/ruby-argon2) by [@technion](https://github.com/technion)
* [Rust](https://github.com/quininer/argon2-rs) by [@quininer](https://github.com/quininer)
* [Rust](https://docs.rs/argonautica/) by [@bcmyers](https://github.com/bcmyers/)
* [C#/.NET CoreCLR](https://github.com/kmaragon/Konscious.Security.Cryptography) by [@kmaragon](https://github.com/kmaragon)
* [Perl](https://github.com/Leont/crypt-argon2) by [@leont](https://github.com/Leont)
* [mruby](https://github.com/Asmod4n/mruby-argon2) by [@Asmod4n](https://github.com/Asmod4n)
* [Swift](https://github.com/ImKcat/CatCrypto) by [@ImKcat](https://github.com/ImKcat)
* [Swift](https://github.com/tmthecoder/Argon2Swift) by [@tmthecoder](https://github.com/tmthecoder)


## Intellectual property

Except for the components listed below, the Argon2 code in this
repository is copyright (c) 2015 Daniel Dinu, Dmitry Khovratovich (main
authors), Jean-Philippe Aumasson and Samuel Neves, and dual licensed under the
[CC0 License](https://creativecommons.org/about/cc0) and the
[Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0). For more info
see the LICENSE file.

The string encoding routines in [`src/encoding.c`](src/encoding.c) are
copyright (c) 2015 Thomas Pornin, and under
[CC0 License](https://creativecommons.org/about/cc0).

The BLAKE2 code in [`src/blake2/`](src/blake2) is copyright (c) Samuel
Neves, 2013-2015, and under
[CC0 License](https://creativecommons.org/about/cc0).

All licenses are therefore GPL-compatible.
