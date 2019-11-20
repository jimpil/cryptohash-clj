(ns cryptohash-clj.proto)

(defprotocol IHashable
  (chash  [this opts])
  (verify [this opts hashed]))

(defprotocol IEncoding
  (to-str   [this])
  (to-chars [this])
  (to-bytes [this])
  (to-hex   [this])
  (to-b64   [this]))

(defprotocol IDecoding
  (from-b64-str [this])
  (from-hex-str [this]))
