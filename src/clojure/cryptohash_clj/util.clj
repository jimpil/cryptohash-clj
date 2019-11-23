(ns cryptohash-clj.util
  (:require [cryptohash-clj.globals :as glb])
  (:import [java.util Arrays]))

(defn aconcat-chars!
  "Concatenates two arrays <a1> & <a2> into a new one and returns it.
   Optionally clears the two input arrays."
  ^chars [^chars a1 ^chars a2]
  (let [a1-length (alength a1)
        a2-length (alength a2)
        ret (char-array (unchecked-add-int a1-length a2-length))]
    (System/arraycopy a1 0 ret 0 a1-length)
    (System/arraycopy a2 0 ret a1-length a2-length)
    (when glb/*stealth?*
      (Arrays/fill a1 \u0000)
      (Arrays/fill a2 \u0000))
    ret))

(def esc-smap
  (let [esc-chars "()&^%$#!?*."]
    (zipmap esc-chars (map (partial str "\\") esc-chars))))

(defn re-pattern-escaping
  [s]
  (->> s
       (replace esc-smap)
       (apply str)
       re-pattern))

#_(defn validate-options!
  [opts spec]
  (when-let [errors (s/explain-data spec opts)]
    (throw (ex-info "Invalid options detected!" errors))))

(defn pow2
  "Returns 2^exp."
  ^long [exp]
  (bit-shift-left 1 exp))
