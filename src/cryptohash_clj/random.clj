(ns cryptohash-clj.random
  (:import (java.security SecureRandom)
           (java.util Random)))

(def ^:dynamic ^Random *PRNG*
  (doto (SecureRandom.)
    (.nextLong)))

(defn next-random-bytes!
 ^bytes [n]
  (let [^bytes random-bs (byte-array n)]
    (.nextBytes *PRNG* random-bs)
    random-bs))

(defmacro with-PRNG
  [prng & body]
  (binding [*PRNG* ~prng]
    ~@body))
