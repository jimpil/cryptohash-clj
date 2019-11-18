(ns cryptohash-clj.impl.scrypt
  (:require [cryptohash-clj.proto :as proto])
  (:import (com.lambdaworks.crypto SCryptUtil)))


(defn- scrypt*
  [raw {:keys [cpu-cost mem-cost pfactor]
        :or {cpu-cost 32768 ;; 2^15
             mem-cost 8
             pfactor 1}}] ;; parallelization param
   (SCryptUtil/scrypt raw cpu-cost mem-cost pfactor))

(defn- hash=
  [raw hashed]
  (SCryptUtil/check raw hashed))

(extend-protocol proto/IHashable

  (Class/forName "[C") ;; char-arrays
  (proto/chash [this opts]
    (scrypt* (apply str this) opts))
  (proto/verify [this _ hashed]
    (hash= (apply str this) hashed))

  String
  (proto/chash [this opts]
    (scrypt* this opts))
  (proto/verify [this opts hashed]
    (hash= this hashed))
  )

(extend-protocol proto/IHashable
  (Class/forName "[B") ;; byte-arrays
  (proto/chash [this opts]
    (scrypt* (String. ^bytes this) opts))
  (proto/verify [this opts hashed]
    (hash= (String. ^bytes this) hashed)))

;;====================================================
(defn chash
  [raw opts]
  (proto/chash raw opts))

(defn verify
  "Compare a raw string with a string encrypted with the [[encrypt]] function.
  Returns true if the string matches, false otherwise."
  [raw hashed]
  (proto/verify raw nil hashed))
