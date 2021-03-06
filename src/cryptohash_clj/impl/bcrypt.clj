(ns cryptohash-clj.impl.bcrypt
  (:require [cryptohash-clj
             [globals :as glb]
             [encode :as enc]])
  (:import [org.bouncycastle.crypto.generators OpenBSDBCrypt]
           [java.util Arrays]
           [java.security MessageDigest]))

(defprotocol IHashable
  (chash*  [this opts])
  (verify* [this hashed opts]))

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
              :truncate (Arrays/copyOf input MAX_BYTES)
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
  [^bytes raw-bytes ^String hashed opts]
  (let [^bytes raw-bytes (cond-> raw-bytes
                                 (> (alength raw-bytes) MAX_BYTES)
                                 (adjust (:long-value opts :sha512)))
        matches? (OpenBSDBCrypt/checkPassword hashed raw-bytes)]
    (glb/fill-bytes! raw-bytes)
    matches?))

(extend-protocol IHashable

  (Class/forName "[C") ;; char-arrays
  (chash* [this opts]
    (bcrypt* (enc/to-bytes this) opts))
  (verify* [this hashed opts]
    (hash= (enc/to-bytes this) hashed opts))

  String
  (chash* [this opts]
    (bcrypt* (enc/to-bytes this) opts))
  (verify* [this hashed opts]
    (hash= (enc/to-bytes this) hashed opts))
  )

(extend-protocol IHashable
  (Class/forName "[B") ;; byte-arrays
  (chash* [this opts]
    (bcrypt* this opts))
  (verify* [this hashed opts]
    (hash= this hashed opts)))
;;=======================================================

(defn chash
  "Main entry point for hashing <x> (String/bytes/chars) using BCrypt.
   <opts> can include a :cpu-cost (default 14), :version (default 2y),
   and a :long-value strategy (defaults to :sha512). Returns String."
  ([x]
   (chash x nil))
  ([x opts]
   (chash* x opts)))

(defn verify
  "Main entry point for verifying that <x> (String/bytes/chars) matches <bcrypt-hashed>.
   If a :long-value strategy (other than the default) was when creating <bcrypt-hashed>
   <opts> must include it too. Returns true/false."
  ([x bcrypt-hashed]
   (verify x bcrypt-hashed nil))
  ([x bcrypt-hashed opts]
   (verify* x (enc/to-str bcrypt-hashed) opts)))
