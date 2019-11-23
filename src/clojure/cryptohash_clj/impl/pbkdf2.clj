(ns cryptohash-clj.impl.pbkdf2
  (:require [cryptohash-clj
             [globals :as glb]
             [equality :as eq]
             [util :as ut]
             [encode :as enc]]
            [clojure.string :as str])
  (:import [javax.crypto SecretKeyFactory]
           [javax.crypto.spec PBEKeySpec]))

(defprotocol IHashable
  (chash  [this opts])
  (verify [this opts hashed]))

(def algorithms
  {:hmac+sha1   "PBKDF2WithHmacSHA1"     ;; JDK7
   :hmac+sha256 "PBKDF2WithHmacSHA256"   ;; JDK8
   :hmac+sha512 "PBKDF2WithHmacSHA512"}) ;; JDK9


(defn- hash=
  [x opts hashed]
  (let [sep           (str (:separator opts glb/SEP))
        sep-pattern   (ut/re-pattern-escaping sep)
        parts         (str/split hashed sep-pattern)
        iterations    (Long/parseLong (parts 0))
        klength       (Long/parseLong (parts 1))
        algorithm     (if (= 5 (count parts))
                        (parts 2)
                        "hmac+sha1")
        salt          (enc/from-b64-str
                        (if (= algorithm "hmac+sha1")
                          (parts 2)
                          (parts 3)))
        raw-hashed (chash x (assoc opts :salt salt
                                        :key-length klength
                                        :iterations iterations
                                        :algo (keyword algorithm)))]
    (eq/hash= raw-hashed hashed)))

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
                    iterations 250000
                    salt-length 16
                    separator glb/SEP}}]

  (when (invalid-separator? separator)
    (throw
      (IllegalArgumentException.
        (format "Invalid separator [%s]!" separator))))

  (let [key-length (or key-length
                       ;; Never request more output than the
                       ;; native output of the inner hashing function
                       (* 8  ;; we want bits
                          (case algo
                            :hmac+sha1   20
                            :hmac+sha256 32
                            :hmac+sha512 64)))
        ^bytes salt (or salt (glb/next-random-bytes! salt-length))
        factory (SecretKeyFactory/getInstance
                  (or (algorithms algo)
                      (throw (IllegalArgumentException.
                               (format "Algorithm [%s] not recognised!" algo)))))
        salt-chars (enc/to-chars salt)
        ;; prepend the salt to the hash
        ^chars salt+x-chars (ut/aconcat-chars! salt-chars pwd) ;; this call will clear both args
        k (PBEKeySpec. salt+x-chars salt iterations key-length)
        salt-b64 (enc/to-b64-str salt)
        hashed-pwd (.getEncoded (.generateSecret factory k))]

    (glb/fill-chars! pwd salt+x-chars)

    (str iterations   separator
         key-length   separator
         (name algo)  separator
         salt-b64     separator
         (enc/to-b64-str hashed-pwd))))

(extend-protocol IHashable

  (Class/forName "[C") ;; char-arrays
  (chash [this opts]
    (pbkdf2* this opts))
  (verify [this opts hashed]
    (hash= this opts hashed))

  String
  (chash [this opts]
    (pbkdf2* (enc/to-chars this) opts))
  (verify [this opts hashed]
    (hash= this opts hashed))
  )

(extend-protocol IHashable
  (Class/forName "[B") ;; byte-arrays
  (chash [this opts]
    (let [ret (pbkdf2*  (enc/to-chars this) opts)]
      (glb/fill-bytes! this)
      ret))
  (verify [this opts hashed]
    (hash= this opts hashed)))

;;===================================
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
