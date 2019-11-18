(ns cryptohash-clj.proto)

(defprotocol IHashable
  (chash  [this opts])
  (verify [this opts hashed]))
