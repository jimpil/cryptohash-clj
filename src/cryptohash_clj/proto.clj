(ns cryptohash-clj.proto)

(defprotocol IHashable
  (chash  [this opts])
  (verify [this opts hashed]))

(defprotocol IConvertible
  (toStr   ^String [this])
  (toChars ^chars  [this])
  (toBytes ^bytes  [this]))

(defprotocol IBaseEncoding
  (toHex      ^bytes [this])
  (toB64      ^bytes [this])
  (fromHexStr ^bytes [this])
  (fromB64Str ^bytes [this]))

