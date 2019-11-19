# cryptohash-clj

<p align="center">
  <img src="https://media.kasperskydaily.com/wp-content/uploads/sites/92/2014/04/06043900/hash.jpg"/>
</p>


## Features

- stealth (optional zero-ing of arrays passed as input or transiently created)
- PBKDF2 (w/ stealth)
- BCRYPT (w/ stealth) 
- SCRYPT (w/o stealth because the underlying Java lib deals with Strings only)
- type consistent (return type matches the input type)
- overly long value support (all algorithms)
- highly configurable (where applicable/possible) and fully spec-ed
- reflection-free (despite the heavy interop)

## Where

TODO 

## Usage
There are two ways to leverage `cryptohash-clj`. 

### cryptohash-clj.api
This namespace contains two multi-methods:

- `hash-with [algo raw options]`
- `verify-with [algo raw options hashed]`

These will delegate to the right implementation according to the first parameter (`:pbkdf2`, `:bcrypt`, `:scrypt`). For example:

```clj
(hash-with :pbkdf2 "_sUpErSeCrEt@1234!_" {:iterations 100})

=> "ZA==$AMA=$hmac+sha256$czrJNQ7CJEbfY5v4$hPuUvHFyGiF3aiE9VBsZZ1AUSehKRbQo"

(verify-with :pbkdf2 "_sUpErSeCrEt@1234!_" {} *1)

=> true
```

### cryptohash-clj.impl.{algorithm}
If you don't want to go via the multi-methods, you can go via the individual implementation namespaces.
Each of the three namespaces (`bcrypt.clj`, `scrypt.clj`, `pbkdf2.clj`) contains two public functions:

- `chash [raw opts]` 
- `verify [raw opts hashed]`

## Details

#### PBKDF2
Can be configured with the following options:

- `:separator`  (defaults to `\$`)
- `:iterations` (defaults to `1,000,000`)
- `:algo` (defaults to `:hmac+sha512`, but `:hmac+sha256` and `:hmac+sha1` are valid choices)
- `:key-length` (defaults to the native output length of `:algo` - 64, 32, 20 respectively)

#### BCRYPT

Can be configured with the following options:

- `:version` (defaults to `:v2a` but `:v2b`, `:v2x`, `:v2y`, `:v2y-nnt` and `:vbc` are valid choices) 
- `:cpu-cost` (defaults to `12`)
- `:long-value-strategy` (defaults to `:sha512`, but `:strict` and `:truncate` are valid choices)

Note that specifically in bcrypt, hasher and verifyer objects are immutable/thread-safe, and therefore can be reused 
(see `bcrypt/new-hasher` and `bcrypt/new-verifyer`). 

#### SCRYPT

Can be configured with the following options:

- `:cpu-cost` (defaults to `15`) 
- `:mem-cost` (defaults to `8`)
- `:pfactor` (parallelization factor - defaults to `1`)

As noted earlier, scrypt is the only algorithm that deals with Strings exclusively (due to the underlying Java lib). 
As a result, there is no point using stealth with it.

## Stealth mode

Stealth mode is controlled by `cryptohash-clj.stealth/*stealth?*` (bound to `true`). 
A convenience macro `with-stealth` is also provided in the same namespace for easy overriding.

## Secure random bytes (for salting etc)

All random bytes are produced via a global instance of `SecureRandom` which lives in `cryptohash-clj.random/*PRNG*`.
A convenience macro `with-PRNG` is also provided in the same namespace for easy overriding.

## Requirements

- Java 8 or above (strict)
- Clojure 1.10.1 or above  (relaxed)

## Alternatives
[crypto-password](https://github.com/weavejester/crypto-password) is the obvious alternative here.
However it lacks an api for bytes/chars (even if the underlying Java lib supports it), stealth-mode, and general configurability.
  

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
