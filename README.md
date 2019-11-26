# cryptohash-clj

<p align="center">
  <img src="https://media.kasperskydaily.com/wp-content/uploads/sites/92/2014/04/06043900/hash.jpg"/>
</p>

## Where

[![Clojars Project](https://clojars.org/cryptohash-clj/latest-version.svg)](https://clojars.org/cryptohash-clj)

## Features

### Major

- [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)
- [BCRYPT](https://en.wikipedia.org/wiki/Bcrypt)
- [SCRYPT](https://en.wikipedia.org/wiki/Scrypt)
- [ARGON2](https://en.wikipedia.org/wiki/Argon2)
- _stealth-mode_ (optional zero-ing of arrays passed as input or transiently created)
- API for dealing with `char`/`byte` arrays as input (required for _stealth-mode_)

### Minor

- Support for values larger than 72 bytes) in BCrypt (truncate or SHA512)
- Highly configurable (with modern/safe defaults)
- Fully spec-ed (but not enforced) 
- Reflection-free (despite the heavy interop)
- Single dependency

## Why
Because Clojure deserves the best crypto-hashers ;)

## Usage
There are two ways to leverage `cryptohash-clj`. 

### cryptohash-clj.api
This namespace contains two multi-methods:

- `hash-with [algo raw options]`
- `verify-with [algo raw options hashed]`

These will delegate to the right implementation according to the first parameter (`:pbkdf2`, `:bcrypt`, `:scrypt`). For example:

```clj
(hash-with :pbkdf2 "_sUpErSeCrEt@1234!_" {:algo :hmac+sha256})
=> "250000$256$hmac+sha256$zv6x/KfjV1318e3kF1aWBQ$qXoIRxVrtVbMnABxh5eTbDfszyc/O4uZIV8QPsLkyhE"

(verify-with :pbkdf2 "_sUpErSeCrEt@1234!_" *1)
=> true

(hash-with :bcrypt "_sUpErSeCrEt@1234!_" {:cpu-cost 8})
=> "$2y$08$0mddgmeilGorJlk.t4JYXu/b/K7S4VOD9LkddsPGyyrJp0TsEaOIu"

(verify-with :bcrypt "_sUpErSeCrEt@1234!_" *1)
=> true
```

Note that all the supported algorithms produce values that include the params in them so strictly speaking there shouldn't be a need
for passing any options to `verify-with`. However, there are some exceptions - for instance in pbkdf2 you can specify a custom separator 
(subject to validation). If you choose to do so, it needs to be known when verifying. Similarly with BCrypt and its `long-value` parameter. For piece of mind you can always rely on the defaults (for those parameters) which will allow you to verify w/o passing options.   

### cryptohash-clj.impl.{algorithm}
If you don't want to go via the multi-methods, you can go via the individual implementation namespaces.
Each of the three namespaces (`bcrypt.clj`, `scrypt.clj`, `pbkdf2.clj`, `argon2.clj`) contains two public functions:

- `chash  ([raw opts] [raw])` 
- `verify ([raw opts hashed] [raw hashed])`

## Configuration details

#### PBKDF2
Can be configured with the following options:

- `:separator`  (defaults to `\$`)
- `:iterations` (defaults to `250,000`)
- `:algo` (defaults to `:hmac+sha512`, but `:hmac+sha256` and `:hmac+sha1` are valid choices)
- `:salt-length` (defaults to `16` bytes)
- `:key-length` (defaults to the native output length of `:algo` - 64, 32 and 20 bytes respectively)

I would advise **against** overriding the default `key-length`.
You should certainly avoid providing a number of bits (bytes * 8) greater than the native output length of your chosen `algo` 
as it makes life easier for an attacker. Providing less is safer, but since it won't save you any computation, it's 
best to stick with the native output length.  

#### BCRYPT

Can be configured with the following options:

- `:version` (defaults to `:v2y` but `:v2a` and `:v2b` are valid choices) 
- `:cpu-cost` (defaults to `13`)
- `:long-value` (defaults to `:sha512`, but `:truncate` is a valid choice)

#### SCRYPT

Can be configured with the following options:

- `:salt-length` (defaults to `16` bytes)
- `:cpu-cost` (defaults to `17`) 
- `:mem-cost` (defaults to `8`)
- `:pfactor` (parallelization factor - defaults to `1`)

#### ARGON2

Can be configured with the following options:

- `:type` (defaults to `:argon2id`)
- `:version` (defaults to `:v13`)
- `:key-length` (defaults to `32` bytes)
- `:salt-length` (defaults to `16` bytes)
- `:secret` (bytes of some secret)
- `:additional` (additional bytes to include)
- `:iterations` (defaults to `100`) 
- `:mem-cost` (defaults to `12`)

## Stealth mode

Stealth mode is controlled by `cryptohash-clj.stealth/*stealth?*` (bound to `true`). 
A convenience macro `with-stealth` is also provided in the same namespace for easy overriding.

## Secure random bytes (for salting etc.)

All random bytes are produced via a global instance of `SecureRandom` which lives in `cryptohash-clj.random/*PRNG*`.
A convenience macro `with-PRNG` is also provided in the same namespace for easy overriding.

## Crypto comparison
Equality comparison is performed in a way that resists timing attacks (see `cryptohash-clj.equality`). 
The length of the data being compared is still discoverable by an attacker, but in the context of 
cryptographic hashing this is not a concern. In fact, many crypto-hashers produce fixed/well-known key lengths. 


## Defaults performance
This will, of course, vary from CPU to CPU, but all the defaults have been tuned to produce a time cost of around 400-500 ms,
on this (relatively modern) MacBook-Pro (2.8-3.8GHz Intel Core i7) from 2017.

## Requirements

- Java 8 or above (strict)
- Clojure 1.10.1 or above  (relaxed)

## Alternatives
[crypto-password](https://github.com/weavejester/crypto-password) is the obvious alternative here.
However it lacks an api for bytes/chars (even if the underlying Java lib supports it), stealth-mode, 
and generally speaking is less configurable. Moreover, it comes with several dependencies.
  
## CLI tool
For some obscure reason the project won't compile to a GRAAL (v19.3.0) native-image . However, I was pleasantly surprised to find out
that with direct-linking enabled, uberjar startup time is dramatically improved. We're talking sub-second here, so even if I do eventually
manage to produce a native-image, it will probably be huge (more than 50MB), and will provide somewhat diminishing returns 
in terms of startup. Sure, it will start fast, but the (direct-linked) uberjar is also rather usable (and much smaller), especially 
for calculating expensive hashes.

Make your own with `lein uberjar` at the top-level directory of this repo (after you've cloned it). 
The resulting uberjar supports a `-h` or `--help` flag. Custom options (if provided) are expected to be valid EDN. 

## License

Copyright © 2019 Dimitrios Piliouras

This program and the accompanying materials are made available under the
terms of the Eclipse Public License 2.0 which is available at
http://www.eclipse.org/legal/epl-2.0.

This Source Code may also be made available under the following Secondary
Licenses when the conditions for such availability set forth in the Eclipse
Public License, v. 2.0 are satisfied: GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or (at your
option) any later version, with the GNU Classpath Exception which is available
at https://www.gnu.org/software/classpath/license.html.
