(ns cryptohash-clj.impl.bcrypt
  (:require [cryptohash-clj
             [globals :as glb]
             [encode :as enc]])
  (:import [org.bouncycastle.crypto.generators OpenBSDBCrypt]
           [java.util Arrays]
           [java.security MessageDigest]))

(defprotocol IHashable
  (chash*  [this opts])
  (verify* [this opts hashed]))

(def VERSIONS
  #{:2a :2b :2y}) ;; '2a' is not backwards compatible

(def ^:const ^long salt-length 16)
(def ^:const ^long MAX_BYTES 72)

(defn- resolve-version
  ^String [k]
  (or (some-> (VERSIONS k) name)
      (throw
        (IllegalArgumentException.
          (format "BCrypt version %s not supported..." k)))))


(defn- adjust
  ^bytes [^bytes input strategy]
  (let [ret (case strategy
              :truncate (-> input enc/to-bytes (Arrays/copyOf MAX_BYTES))
              ;; produces 64 bytes - well within the limit
              :sha512 (let [md (MessageDigest/getInstance "SHA-512")] ;; 64 bytes
                        (.digest md input)))]
    (glb/fill-bytes! input)
    ret))

(defn- bcrypt*
  ^String
  [^bytes raw-input
   {:keys [version long-value cpu-cost salt]
    :or {version :2y ;; doesn't really matter
         long-value :sha512
         cpu-cost 14}}] ;; less than 12 is not safe in 2019

  (let [v (resolve-version version)
        ^bytes salt (or salt (glb/next-random-bytes! salt-length))
        input-length (alength raw-input)
        ^bytes input (cond-> raw-input
                             (> input-length MAX_BYTES)
                             (adjust long-value))
        hashed (OpenBSDBCrypt/generate v input salt (int cpu-cost))]
    (glb/fill-bytes! input)
    hashed))

(defn- hash=
  [^chars raw-chars ^String hashed]
  (OpenBSDBCrypt/checkPassword hashed raw-chars))

(extend-protocol IHashable

  (Class/forName "[C") ;; char-arrays
  (chash* [this opts]
    (bcrypt* (enc/to-bytes this) opts))
  (verify* [this _ hashed]
    (hash= this hashed))

  String
  (chash* [this opts]
    (bcrypt* (enc/to-bytes this) opts))
  (verify* [this opts hashed]
    (hash= (enc/to-chars this) hashed))
  )

(extend-protocol IHashable
  (Class/forName "[B") ;; byte-arrays
  (chash* [this opts]
    (bcrypt* this opts))
  (verify* [this opts hashed]
    (hash= (enc/to-chars this) hashed)))
;;=======================================================

(defn chash
  "Main entry point for hashing <x> (String/bytes/chars) using BCrypt.
   <opts> must inlude a :cost key and either a pre-constructed :hasher,
   or options per `new-hasher`. The return value type is dictated by <x>."
  ([x]
   (chash x nil))
  ([x opts]
   (chash* x opts)))

(defn verify
  "Main entry point for verifying that <x> (String/bytes/chars) matches <hashed>.
   <opts> must match the ones used to produce <hashed> and can include a
   pre-constructed :verifyer. Returns true/false."
  ([x hashed]
   (verify x nil hashed))
  ([x opts hashed]
   (verify* x opts (enc/to-str hashed))))
