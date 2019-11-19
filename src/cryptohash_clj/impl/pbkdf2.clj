(ns cryptohash-clj.impl.pbkdf2
  (:require [cryptohash-clj
             [proto :as proto]
             [random :as random]
             [util :as ut]
             [stealth :as stealth]]
            [clojure.string :as str])
  (:import (javax.crypto SecretKeyFactory)
           (javax.crypto.spec PBEKeySpec)
           (java.util Arrays)))

(defonce algorithms
  {:hmac+sha1   "PBKDF2WithHmacSHA1"     ;; JDK7
   :hmac+sha256 "PBKDF2WithHmacSHA256"   ;; JDK8
   :hmac+sha512 "PBKDF2WithHmacSHA512"}) ;; JDK9

(defn- hash=
  "Test whether two sequences of characters or bytes are equal in a way that
  protects against timing attacks. Note that this does not prevent an attacker
  from discovering the *length* of the data being compared."
  [a b]
  (let [a (seq (map int a))
        b (seq (map int b))]
    (or
      (and (nil? a)
           (nil? b))
      (and (some? a)
           (some? b)
           (= (count a)
              (count b))
           (zero? (reduce bit-or (map bit-xor a b))))
      false)))


(defn- int->b64
  [^long i]
  (-> i
      BigInteger/valueOf
      .toByteArray
      ut/bytes->base64-str))

(defn- b64->int
  [s]
  (->> (ut/base64-str->bytes s)
       (BigInteger. 1)
       long))

(defn- check-hash
  [x opts encrypted]
  (let [sep           (str (:separator opts \$))
        sep-pattern   (ut/re-pattern-escaping sep)
        parts         (str/split encrypted sep-pattern)
        iterations    (b64->int (parts 0))
        klength       (b64->int (parts 1))
        algorithm     (if (= (count parts) 5)
                        (parts 2)
                        "hmac+sha1")
        salt          (ut/base64-str->bytes
                        (if (= algorithm "hmac+sha1")
                          (parts 2)
                          (parts 3)))
        raw-encrypted (proto/chash x (assoc opts :salt salt
                                                 :key-length klength
                                                 :iterations iterations
                                                 :algorithm (keyword algorithm)))]
    (hash= raw-encrypted encrypted)))

(defn- invalid-separator?
  [c]
  (some?
    (re-matches
      #"[A-Za-z0-9\+\/=]" ;; base64 alphabet
      (str c))))

(defn- pbkdf2*
  "Get a PBKDF2 (key-stretching) hash for the given string <pwd>.
   A good/similar alternative to bcrypt. Options include:

  :algo - The algorithm to use. See `treajure.crypto-hashing/pbkdf2-algorithms`
          for the supported algorithms. Defaults to `:hmac+sha512`.

  :salt - The salt to use (a byte-array or String). Defaults to 12 random bytes (generated via `SecureRandom`).

  :key-length - How long the key should be. Defaults to 192 (bits).

  :iterations - How many iterations to use. The bigger this is, the more expensive the calculation.
                Defaults to 1E6.

  :separator - The character to use between the various returned parts. Defaults to '$'.

  Returns the hashed password prefixed with salt (in base64), the iterations and the key-length,
  separated by the :separator character."

  ^String
  [^chars pwd {:keys [algo salt salt-length key-length iterations separator]
               :or {algo :hmac+sha512
                    iterations 1000000 ;; 1E6 iterations is a reasonable starting point
                    salt-length 16
                    separator \$}}]

  (when (invalid-separator? separator)
    (throw
      (IllegalArgumentException.
        (format "Invalid separator [%s]!" separator))))

  (let [key-length (or key-length
                       ;; Never request more output than the
                       ;; native output of the inner hashing function
                       (case algo ;; we want bits so multiply by 8
                         :hmac+sha1   (* 20 8)
                         :hmac+sha256 (* 32 8)
                         :hmac+sha512 (* 64 8)))
        ^bytes salt (or salt (random/next-random-bytes! salt-length))
        factory (SecretKeyFactory/getInstance
                  (or (algorithms algo)
                      (throw (IllegalArgumentException.
                               (format "Algorithm [%s] not recognised!" algo)))))
        salt-chars (ut/bytes->chars salt)
        ;; prepend the salt to the hash
        ^chars salt+x-chars (ut/aconcat-chars! salt-chars pwd) ;; this call will clear both args
        k (PBEKeySpec. salt+x-chars salt iterations key-length)
        salt-b64 (ut/bytes->base64-str salt)
        hashed-pwd (.getEncoded (.generateSecret factory k))]

    (when stealth/*stealth?*
      (Arrays/fill salt+x-chars \u0000)
      (Arrays/fill salt (byte 0)))

    (str (int->b64 iterations) separator
         (int->b64 key-length) separator
         (name algo)           separator
         salt-b64              separator
         (ut/bytes->base64-str hashed-pwd))))

(extend-protocol proto/IHashable

  (Class/forName "[C") ;; char-arrays
  (proto/chash [this opts]
    (.toCharArray (pbkdf2* this opts)))
  (proto/verify [this opts hashed]
    (check-hash this opts hashed))

  String
  (proto/chash [this opts]
    (pbkdf2* (.toCharArray this) opts))
  (proto/verify [this opts hashed]
    (check-hash this opts hashed))
  )

(extend-protocol proto/IHashable
  (Class/forName "[B") ;; byte-arrays
  (proto/chash [this opts]
    (let [ret (pbkdf2*  (ut/bytes->chars this) opts)]
      (when stealth/*stealth?*
        (Arrays/fill ^bytes this (byte 0)))
      (.getBytes ret)))
  (proto/verify [this opts hashed]
    (proto/verify
        (ut/bytes->chars this)
        opts
        (ut/bytes->chars hashed))))

;;===================================
(defn chash
  "Main entry point for hashing <x> (String/bytes/chars) using PBKDF2.
   <opts> must inlude."
  [x opts]
  (proto/chash x opts))

(defn verify
  [x opts hashed]
  (proto/verify x opts (ut/to-str hashed)))
