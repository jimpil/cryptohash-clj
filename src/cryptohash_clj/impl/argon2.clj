(ns cryptohash-clj.impl.argon2
  (:require [clojure.string :as str]
            [cryptohash-clj
             [proto :as proto]
             [globals :as glb]
             [equality :as eq]
             [encode :as enc]])
  (:import [org.bouncycastle.crypto.generators Argon2BytesGenerator]
           [org.bouncycastle.crypto.params Argon2Parameters Argon2Parameters$Builder]))

(def VERSIONS
  {:v10 Argon2Parameters/ARGON2_VERSION_10
   :v13 Argon2Parameters/ARGON2_VERSION_13})

(def TYPES
  {:argon2d  Argon2Parameters/ARGON2_d
   :argon2i  Argon2Parameters/ARGON2_i
   :argon2id Argon2Parameters/ARGON2_id})

(defn- argon2*
  ^String
  [^chars raw
   {:keys [type version iterations mem-cost pfactor key-length salt salt-length additional secret]
    :or {type :argon2id
         version :v13
         key-length 32
         salt-length 16
         iterations 1000
         mem-cost 12}}]
  (let [salt (or salt (glb/next-random-bytes! salt-length))
        params (cond-> (Argon2Parameters$Builder. (TYPES type))
                       true (.withVersion (VERSIONS version))
                       true (.withIterations iterations)
                       true (.withMemoryPowOfTwo mem-cost)
                       pfactor (.withParallelism pfactor)
                       additional (.withAdditional additional)
                       secret (.withSecret secret)
                       true (.withSalt salt)
                       true .build)
        gen (doto (Argon2BytesGenerator.)
              (.init params))
        K (byte-array key-length)]
    (.generateBytes gen raw K 0 ^long key-length)
    (str
      (enc/to-b64-str iterations) glb/SEP
      (enc/to-b64-str mem-cost) glb/SEP
      (name type) glb/SEP
      (name version) glb/SEP
      (enc/to-b64-str salt) glb/SEP
      (enc/to-b64-str K) glb/SEP
      (some-> pfactor enc/to-b64-str) glb/SEP
      (some-> secret enc/to-b64-str) glb/SEP
      (some-> additional enc/to-b64-str))))

(defn- hash=
  [raw hashed]
  (let [parts (str/split hashed #"\$")
        iterations (enc/b64->int (parts 0))
        mem-cost   (enc/b64->int (parts 1))
        type       (keyword (parts 2))
        version    (keyword (parts 3))
        salt (enc/from-b64-str (parts 4))
        ;K    (ut/base64-str->bytes (parts 5))
        pfactor    (get parts 6)
        secret     (get parts 7)
        additional (get parts 8)
        opts (cond-> {:iterations iterations
                      :mem-cost mem-cost
                      :type type
                      :version version
                      :salt salt}
                     pfactor    (assoc :pfactor    (enc/b64->int pfactor))
                     secret     (assoc :secret     (enc/from-b64-str secret))
                     additional (assoc :additional (enc/from-b64-str additional)))
        raw-hashed (proto/chash raw opts)]
    (eq/hash= raw-hashed hashed)))


(extend-protocol proto/IHashable

  (Class/forName "[C") ;; char-arrays
  (proto/chash [this opts]
    (argon2* this opts))
  (proto/verify [this _ hashed]
    (hash= this hashed))

  String
  (proto/chash [this opts]
    (argon2* (enc/to-chars this) opts))
  (proto/verify [this opts hashed]
    (hash= this hashed))
  )

(extend-protocol proto/IHashable
  (Class/forName "[B") ;; byte-arrays
  (proto/chash [this opts]
    (argon2* (enc/to-chars this) opts))
  (proto/verify [this opts hashed]
    (hash= this hashed)))
;;=======================================================

(defn chash
  "Main entry point for hashing <x> (String/bytes/chars) using Argon2."
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
