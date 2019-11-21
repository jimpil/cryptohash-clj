(ns cryptohash-clj.impl.bcrypt
  (:require [cryptohash-clj
             [proto :as proto]
             [globals :as glb]
             [encode :as enc]])
  (:import [org.bouncycastle.crypto.generators OpenBSDBCrypt]
           [java.util Arrays]
           [java.security MessageDigest]))

(defonce VERSIONS
  #{:2a :2b :2y}) ;; '2a' is not backwards compatible

(defn- resolve-version
  ^String [k]
  (or (some-> (VERSIONS k) name)
      (throw
        (IllegalArgumentException.
          (format "BCrypt version %s not supported..." k)))))


(defn- adjust
  ^bytes [^chars input strategy]
  (case strategy
    :truncate (-> input enc/to-bytes (Arrays/copyOf 72))
    ;; produces 32 bytes (44 ASCII chars in base64)
    :sha256 (let [md (MessageDigest/getInstance "SHA-256")
                  digest (.digest md (enc/to-bytes input))
                  ret (enc/to-b64 digest)]
              (when glb/*stealth?*
                (Arrays/fill digest (byte 0)))
              ret)))


(defn- bcrypt*
  ^String
  [^bytes input
   {:keys [version long-value cpu-cost salt salt-length]
    :or {version :2y ;; doesn't really matter
         long-value :sha256
         salt-length 16
         cpu-cost 13}}] ;; less than 12 is not safe in 2019


  (let [v (resolve-version version)
        ^bytes salt (or salt (glb/next-random-bytes! salt-length))
        input-length (alength input)
        ^chars input (cond-> input
                             (> input-length 72)
                             (adjust long-value)
                             true enc/to-chars)]
    (OpenBSDBCrypt/generate v input salt cpu-cost)))


(defn- hash=
  [^chars raw-chars ^String hashed]
  (OpenBSDBCrypt/checkPassword hashed raw-chars))

(extend-protocol proto/IHashable

  (Class/forName "[C") ;; char-arrays
  (chash [this opts]
    (bcrypt* (enc/to-bytes this) opts))
  (verify [this _ hashed]
    (hash= this hashed))

  String
  (chash [this opts]
    (bcrypt* (.getBytes this) opts))
  (verify [this opts hashed]
    (hash= (.toCharArray this) hashed))
  )

(extend-protocol proto/IHashable
  (Class/forName "[B") ;; byte-arrays
  (chash [this opts]
    (bcrypt* this opts))
  (verify [this opts hashed]
    (hash= (enc/to-chars this) hashed)))
;;=======================================================

(defn chash
  "Main entry point for hashing <x> (String/bytes/chars) using BCrypt.
   <opts> must inlude a :cost key and either a pre-constructed :hasher,
   or options per `new-hasher`. The return value type is dictated by <x>."
  ([x]
   (chash x nil))
  ([x opts]
   (proto/chash x opts)))

(defn verify
  "Main entry point for verifying that <x> (String/bytes/chars) matches <hashed>.
   <opts> must match the ones used to produce <hashed> and can include a
   pre-constructed :verifyer. Returns true/false."
  ([x hashed]
   (verify x nil hashed))
  ([x opts hashed]
   (proto/verify x opts (enc/to-str hashed))))
