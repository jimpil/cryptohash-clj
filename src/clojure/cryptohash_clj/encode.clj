(ns cryptohash-clj.encode
  (:require [cryptohash-clj
             [globals :as glb]])
  (:import [java.nio.charset Charset]
           [java.nio ByteBuffer CharBuffer]
           [java.util Base64$Decoder Base64$Encoder Base64 Arrays]
           [org.bouncycastle.util.encoders Hex]))

(def ^Charset DEFAULT-CHARSET
  (Charset/forName "UTF-8"))

(def ^Base64$Encoder PLAIN-B64-ENCODER
  (.withoutPadding
    (Base64/getEncoder)))

(def ^Base64$Decoder PLAIN-B64-DECODER
  (Base64/getDecoder))

(defn- bytes->base64
  "Encodes the specified byte array into bytes using the Base64 encoding scheme."
  (^bytes [^bytes bs]
   (bytes->base64 bs PLAIN-B64-ENCODER))
  (^bytes [^bytes bs ^Base64$Encoder encoder]
   (.encode encoder bs)))

#_(defn- bytes->base64-str
  "Encodes the specified byte array into a String using the Base64 encoding scheme."
  (^String [^bytes bs]
   (bytes->base64-str bs PLAIN-B64-ENCODER))
  (^String [^bytes bs encoder]
   (String. (bytes->base64 bs encoder))))


(defn- base64-str->bytes
  "Decodes a Base64 encoded String into a byte array using the Base64 encoding scheme."
  (^bytes [^String s]
   (base64-str->bytes s PLAIN-B64-DECODER))
  (^bytes [^String s ^Base64$Decoder decoder]
   (.decode decoder s)))

(defn- bytes->chars
  "Given an array of bytes <bs> and some <charset>
   returns the correspond characters, optionally without leaving any traces of the conversion
   (e.g. allocating a String object)."
  (^chars [^bytes bs]
   (bytes->chars DEFAULT-CHARSET bs))
  (^chars [^Charset cs ^bytes bs]
   (let [byte-buffer (ByteBuffer/wrap bs)
         char-buffer (.decode cs byte-buffer)
         ret (Arrays/copyOfRange (.array char-buffer)
                                 (.position char-buffer)
                                 (.limit char-buffer))]
     (when glb/*stealth?*
       (Arrays/fill (.array char-buffer) \u0000))
     ret)))

(defn- chars->bytes
  "Given an array of characters <cs> and some character-encoding <encoding>
   returns the corresponding bytes, optionally without leaving any traces of the conversion
   (e.g. allocating a String object)."
  (^bytes [^chars xs]
   (chars->bytes DEFAULT-CHARSET xs))
  (^bytes [^Charset cs ^chars xs]
   (let [char-buffer (CharBuffer/wrap xs)
         byte-buffer (.encode cs char-buffer)
         ret (Arrays/copyOfRange (.array byte-buffer)
                                 (.position byte-buffer)
                                 (.limit byte-buffer))]
     (when glb/*stealth?*
       (Arrays/fill (.array byte-buffer) (byte 0)))
     ret)))

;;==========================================
(defprotocol IConvertible
  (toStr   ^String [this])
  (toChars ^chars  [this])
  (toBytes ^bytes  [this]))

(defprotocol IBaseEncoding
  (toHex      ^bytes [this])
  (toB64      ^bytes [this])
  (fromHexStr ^bytes [this])
  (fromB64Str ^bytes [this]))

(extend-type (Class/forName "[C")
  IConvertible
  (toChars [this] this)
  (toStr [this] (String. ^chars this))
  (toBytes [this] (chars->bytes this))
  IBaseEncoding
  (toB64 [this] (bytes->base64 (toBytes this)))
  (toHex [this] (toHex (toBytes this)))
  )

(extend-type (Class/forName "[B")
  IConvertible
  (toChars [this] (bytes->chars this))
  (toStr [this] (String. ^bytes this))
  (toBytes [this] this)
  IBaseEncoding
  (toB64 [this] (bytes->base64 this))
  (toHex [this] (Hex/encode ^bytes this))
  )


(extend-type String
  IConvertible
  (toChars [this] (.toCharArray this))
  (toStr   [this] this)
  (toBytes [this] (.getBytes this))
  IBaseEncoding
  (toB64   [this] (bytes->base64 (toBytes this)))
  (toHex   [this] (toHex (toBytes this)))
  (fromB64Str [this] (base64-str->bytes this))
  (fromHexStr [this] (Hex/decode ^String this))
  )

(extend-type Long
  IConvertible
  (toStr   [this] (.toString ^Long this))
  (toChars [this] (.toCharArray (toStr this)))
  (toBytes [this] (-> (ByteBuffer/allocate 8) 
                      (.putLong this) 
                      .array))
  IBaseEncoding
  (toB64 [this] (-> this
                    BigInteger/valueOf
                    .toByteArray
                    toB64))
  (toHex [this] (toHex (toBytes this)))
  )

;;===========================================================

(defn to-chars
  ^chars [x]
  (toChars x))

(defn to-bytes
  ^bytes [x]
  (toBytes x))

(defn to-str
  ^String [x]
  (toStr x))

(defn to-b64
  ^bytes [x]
  (toB64 x))

(defn to-b64-str
  ^String [x]
  (toStr (toB64 x)))

(defn to-hex
  ^bytes [x]
  (toHex x))

(defn to-hex-str
  ^String [x]
  (toStr (toHex x)))

(defn from-b64-str
  ^bytes [x]
  (fromB64Str x))

(defn int-from-b64-str
  ^long [x]
  (long
    (BigInteger. 1 (fromB64Str x))))

(defn from-hex-str
  ^bytes [x]
  (fromHexStr x))

(defn int-from-hex-str
  ^long [x]
  (long
    (BigInteger. 1 (fromHexStr x))))