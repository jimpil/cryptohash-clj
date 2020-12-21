(ns cryptohash-clj.impl.scrypt
  (:require [cryptohash-clj
             [encode :as enc]
             [util :as ut]]
            [cryptohash-clj.globals :as glb]
            [cryptohash-clj.equality :as eq]
            [clojure.string :as str])
  (:import [org.bouncycastle.crypto.generators SCrypt]))

(defprotocol IHashable
  (chash*  [this opts])
  (verify* [this hashed opts]))

(defn- scrypt*
  ^String
  [^bytes raw
   {:keys [cpu-cost key-length mem-cost pfactor salt salt-length]
    :or {cpu-cost 17
         mem-cost 8
         key-length 192
         salt-length 16
         pfactor 1}}] ;; parallelization factor
  (let [^bytes salt (or salt (glb/next-random-bytes! salt-length))
        N (ut/pow2 cpu-cost)
        K (SCrypt/generate raw salt N mem-cost pfactor key-length)
        saltb64 (enc/to-b64-str salt)]

    (glb/fill-bytes! raw)
    (str
      cpu-cost   glb/SEP
      mem-cost   glb/SEP
      pfactor    glb/SEP
      key-length glb/SEP
      saltb64    glb/SEP
      (enc/to-b64-str K))))

(defn- hash=
  [^chars raw ^String hashed]
  (let [parts (str/split hashed #"\$")
        [cpu-cost mem-cost pfactor klength]
        (map (comp #(Long/parseLong %) parts) (range 4))
        salt (enc/from-b64-str (parts 4))
        raw-hashed (chash* raw {:salt      salt
                                :key-length klength
                                :cpu-cost   cpu-cost
                                :mem-cost   mem-cost
                                :pfactor    pfactor})]
    (eq/hash= raw-hashed hashed)))

(extend-protocol IHashable

  (Class/forName "[C") ;; char-arrays
  (chash* [this opts]
    (scrypt* (enc/to-bytes this) opts))
  (verify* [this hashed _]
    (hash= this hashed))

  String
  (chash* [this opts]
    (scrypt* (enc/to-bytes this) opts))
  (verify* [this hashed _]
    (hash= (enc/to-chars this) hashed))
  )

(extend-protocol IHashable
  (Class/forName "[B") ;; byte-arrays
  (chash* [this opts]
    (scrypt* this opts))
  (verify* [this hashed _]
    (hash= (enc/to-chars this) hashed)))

;;====================================================
(defn chash
  "Main entry point for hashing <x> (String/bytes/chars) using SCrypt.
   <opts> can include a :cpu-cost (default 17), :memcost (default 8),
   :pfactor (default 1), :key-length (default 192), and  :salt-length
   (default 16). Returns String."
  ([x]
   (chash x nil))
  ([x opts]
   (chash* x opts)))

(defn verify
  "Main entry point for verifying that <x> (String/bytes/chars)
   matches <scrypt-hashed>. Returns true/false."
  ([x scrypt-hashed]
   (verify x scrypt-hashed nil))
  ([x scrypt-hashed opts]
   (verify* x (enc/to-str scrypt-hashed) opts)))
