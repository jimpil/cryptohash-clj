(ns cryptohash-clj.util
  (:require [cryptohash-clj.stealth :as stealth]
            [clojure.spec.alpha :as s])
  (:import (java.nio ByteBuffer)
           (java.nio.charset Charset)
           (java.util Arrays Base64$Encoder Base64 Base64$Decoder)))

(def ^Charset DEFAULT-CHARSET
  (Charset/forName "UTF-8"))

(defn bytes->base64-str
  "Encodes the specified byte array into a String using the Base64 encoding scheme."
  (^String [^bytes bs]
   (bytes->base64-str bs :plain))
  (^String [^bytes bs encoder]
   (let [^Base64$Encoder enc (case encoder
                               :mime (Base64/getMimeEncoder)
                               :url  (Base64/getUrlEncoder)
                               :plain (Base64/getEncoder)
                               encoder)]
     (.encodeToString enc bs))))

(defn base64-str->bytes
  "Decodes a Base64 encoded String into a byte array using the Base64 encoding scheme."
  (^bytes [^String s]
   (base64-str->bytes s :plain))
  (^bytes [^String s decoder]
   (let [^Base64$Decoder deco (case decoder
                                :mime (Base64/getMimeDecoder)
                                :url  (Base64/getUrlDecoder)
                                :plain (Base64/getDecoder)
                                decoder)]
     (.decode deco s))))

(defn bytes->chars
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
     (when stealth/*stealth?*
       (Arrays/fill (.array char-buffer) \u0000))
     ret)))

(defn aconcat-chars!
  "Concatenates two arrays <a1> & <a2> into a new one and returns it.
   Optionally clears the two input arrays."
  ^chars [^chars a1 ^chars a2]
  (let [a1-length (alength a1)
        a2-length (alength a2)
        ret (char-array (unchecked-add-int a1-length a2-length))]
    (System/arraycopy a1 0 ret 0 a1-length)
    (System/arraycopy a2 0 ret a1-length a2-length)
    (when stealth/*stealth?*
      (Arrays/fill a1 \u0000)
      (Arrays/fill a2 \u0000))
    ret))

(defonce esc-smap
  (let [esc-chars "()&^%$#!?*."]
    (zipmap esc-chars (map (partial str "\\") esc-chars))))

(defn re-pattern-escaping
  [s]
  (->> s
       (replace esc-smap)
       (apply str)
       re-pattern))

(defn validate-options!
  [opts spec]
  (when-let [errors (s/explain-data spec opts)]
    (throw (ex-info "Invalid options detected!" errors))))