(ns cryptohash-clj.impl.scrypt
  (:require [cryptohash-clj
             [proto :as proto]
             [encode :as enc]
             [util :as ut]]
            [cryptohash-clj.globals :as glb]
            [cryptohash-clj.equality :as eq]
            [clojure.string :as str])
  (:import [org.bouncycastle.crypto.generators SCrypt]
           (java.util Arrays)))


(defn- scrypt*
  ^String
  [^bytes raw
   {:keys [cpu-cost key-length mem-cost pfactor salt salt-length]
    :or {cpu-cost 15
         mem-cost 8
         key-length 192
         salt-length 16
         pfactor 1}}] ;; parallelization factor
  (let [^bytes salt (or salt (glb/next-random-bytes! salt-length))
        N (ut/pow2 cpu-cost)
        K (SCrypt/generate raw salt N mem-cost pfactor key-length)
        saltb64 (enc/to-b64-str salt)]
    (when glb/*stealth?*
      (Arrays/fill raw  (byte 0))
      (Arrays/fill salt (byte 0)))
    (str
      (enc/to-b64-str cpu-cost)   glb/SEP
      (enc/to-b64-str mem-cost)   glb/SEP
      (enc/to-b64-str pfactor)    glb/SEP
      (enc/to-b64-str key-length) glb/SEP
      saltb64                     glb/SEP
      (enc/to-b64-str K))))

(defn- hash=
  [^chars raw ^String hashed]
  (let [parts (str/split hashed #"\$")
        [cpu-cost mem-cost pfactor klength]
        (map (comp enc/int-from-b64-str parts) (range 4))
        salt (enc/from-b64-str (parts 4))
        raw-hashed (proto/chash raw {:salt salt
                                     :key-length klength
                                     :cpu-cost cpu-cost
                                     :mem-cost mem-cost
                                     :pfactor pfactor})]
    (eq/hash= raw-hashed hashed)))

(extend-protocol proto/IHashable

  (Class/forName "[C") ;; char-arrays
  (proto/chash [this opts]
    (scrypt* (enc/to-bytes this) opts))
  (proto/verify [this _ hashed]
    (hash= this hashed))

  String
  (proto/chash [this opts]
    (scrypt* (enc/to-bytes this) opts))
  (proto/verify [this opts hashed]
    (hash= (enc/to-chars this) hashed))
  )

(extend-protocol proto/IHashable
  (Class/forName "[B") ;; byte-arrays
  (proto/chash [this opts]
    (scrypt* this opts))
  (proto/verify [this opts hashed]
    (hash= (enc/to-chars this) hashed)))

;;====================================================
(defn chash
  ([x]
   (chash x nil))
  ([x opts]
   (proto/chash x opts)))

(defn verify
  "Compare a raw string with a string encrypted with the [[encrypt]] function.
  Returns true if the string matches, false otherwise."
  ([x hashed]
   (verify x nil hashed))
  ([x opts hashed]
   (proto/verify x opts (enc/to-str hashed))))
