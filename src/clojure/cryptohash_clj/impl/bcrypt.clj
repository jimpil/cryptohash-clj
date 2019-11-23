(ns cryptohash-clj.impl.bcrypt
  (:require [cryptohash-clj
             [globals :as glb]
             [encode :as enc]]
            [clojure.string :as str]
            [cryptohash-clj.equality :as eq])
  (:import [org.bouncycastle.crypto.generators BCrypt]
           [cryptohash_clj BCryptEncode]
           [java.util Arrays]
           [java.security MessageDigest]))

(defprotocol IHashable
  (chash  [this opts])
  (verify [this opts hashed]))

(defonce VERSIONS
  #{:2a :2b :2y}) ;; '2a' is not backwards compatible

(defn- resolve-version
  ^String [k]
  (or (some-> (VERSIONS k) name)
      (throw
        (IllegalArgumentException.
          (format "BCrypt version %s not supported..." k)))))


(defn- adjust
  ^bytes [^bytes input strategy]
  (case strategy
    :truncate (-> input enc/to-bytes (Arrays/copyOf 72))
    ;; produces 64 bytes - well within the limit
    :sha512 (let [md (MessageDigest/getInstance "SHA-512")] ;; 64 bytes
              (.digest md input))))

(defn- bcrypt*
  ^String
  [^bytes input
   {:keys [version long-value cpu-cost salt]
    :or {version :2y ;; doesn't really matter
         long-value :sha512
         cpu-cost 13}}] ;; less than 12 is not safe in 2019

  (let [v (resolve-version version)
        ^bytes salt (or salt (glb/next-random-bytes! 16))
        ^bytes input (cond-> input
                             (> (alength input) 72)
                             (adjust long-value))
        hashed (BCrypt/generate input salt cpu-cost)
        cost-str (cond->> cpu-cost
                          (> 10 cpu-cost)
                          (str 0))]
    (str glb/SEP v glb/SEP
         cost-str  glb/SEP
         (BCryptEncode/encodeData salt)
         (BCryptEncode/encodeData hashed))))


(defn- hash=
  [^chars raw-chars ^String hashed]
  (let [parts (str/split hashed #"\$")
        [v c s+h] (next (map parts (range 4)))
        salt-b64 (subs s+h 0 22)
        ;K (subs s+h 22 53)
        raw-hashed (chash raw-chars {:version  (keyword v)
                                     :cpu-cost (Long/parseLong c)
                                     :salt (BCryptEncode/decodeSaltString salt-b64)})]
    (eq/hash= hashed raw-hashed)))

(extend-protocol IHashable

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

(extend-protocol IHashable
  (Class/forName "[B") ;; byte-arrays
  (chash [this opts]
    (bcrypt* this opts))
  (verify [this opts hashed]
    (hash= (enc/to-chars this) hashed)))
;;=======================================================

(defn chash*
  "Main entry point for hashing <x> (String/bytes/chars) using BCrypt.
   <opts> must inlude a :cost key and either a pre-constructed :hasher,
   or options per `new-hasher`. The return value type is dictated by <x>."
  ([x]
   (chash* x nil))
  ([x opts]
   (chash x opts)))

(defn verify*
  "Main entry point for verifying that <x> (String/bytes/chars) matches <hashed>.
   <opts> must match the ones used to produce <hashed> and can include a
   pre-constructed :verifyer. Returns true/false."
  ([x hashed]
   (verify* x nil hashed))
  ([x opts hashed]
   (verify x opts (enc/to-str hashed))))