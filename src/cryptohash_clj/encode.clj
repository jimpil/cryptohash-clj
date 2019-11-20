(ns cryptohash-clj.encode
  (:require [cryptohash-clj
             [proto :as proto]
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

(defn- bytes->base64-str
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

(defn- int->b64
  [^long i]
  (-> i
      BigInteger/valueOf
      .toByteArray
      bytes->base64-str))

(defn b64->int
  [s]
  (->> (base64-str->bytes s)
       (BigInteger. 1)
       long))
;;==========================================
(extend-protocol proto/IEncoding
  (Class/forName "[C")
  (proto/to-chars [this] this)
  (proto/to-str   [this] (apply str this))
  (proto/to-bytes [this] (chars->bytes this))
  (proto/to-b64   [this] (bytes->base64 (proto/to-bytes this)))
  (proto/to-hex   [this] (proto/to-hex (proto/to-bytes this))))

(extend-protocol proto/IEncoding
  (Class/forName "[B")
  (proto/to-chars [this] (bytes->chars this))
  (proto/to-str   [this] (String. ^bytes this))
  (proto/to-bytes [this] this)
  (proto/to-b64   [this] (bytes->base64 this))
  (proto/to-hex   [this] (Hex/encode ^bytes this)))

(extend-protocol proto/IEncoding
  String
  (proto/to-chars [this] (.toCharArray ^String this))
  (proto/to-str   [this] this)
  (proto/to-bytes [this] (.getBytes ^String this))
  (proto/to-b64   [this] (bytes->base64 (proto/to-bytes this)))
  (proto/to-hex   [this] (proto/to-hex (proto/to-bytes this)))

  Long
  (to-bytes [this] (-> (ByteBuffer/allocate 8)
                       (.putLong this)
                       .array))
  (proto/to-b64 [this] (int->b64 this))
  )

(extend-protocol proto/IDecoding
  String
  (from-b64-str [this] (base64-str->bytes this))
  (from-hex-str [this] (Hex/decode ^String this))

  Long
  (from-b64-str [this] (b64->int this))
  (from-hex-str [this] (Hex/decode ^bytes (proto/to-bytes this)))
  )
;;===========================================================

(defn to-chars
  ^chars [x]
  (proto/to-chars x))

(defn to-bytes
  ^bytes [x]
  (proto/to-bytes x))

(defn to-str
  ^String [x]
  (proto/to-str x))

(defn to-b64
  ^bytes [x]
  (proto/to-b64 x))

(defn to-b64-str
  ^String [x]
  (proto/to-str (proto/to-b64 x)))

(defn to-hex
  ^bytes [x]
  (proto/to-hex x))

(defn to-hex-str
  ^String [x]
  (proto/to-str (proto/to-hex x)))

(defn from-b64-str
  ^bytes [x]
  (proto/from-b64-str x))

(defn from-hex-str
  ^bytes [x]
  (proto/from-hex-str x))