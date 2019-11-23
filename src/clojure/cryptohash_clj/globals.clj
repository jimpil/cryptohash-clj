(ns cryptohash-clj.globals
  (:import [java.security SecureRandom]
           [java.util Random]))

(def ^:const SEP \$)

(def ^:dynamic ^Random *PRNG*
  (SecureRandom.))

(defn next-random-bytes!
  ^bytes [n]
  (let [^bytes random-bs (byte-array n)]
    (.nextBytes *PRNG* random-bs)
    random-bs))

(defmacro with-PRNG
  [prng & body]
  (binding [*PRNG* ~prng]
    ~@body))

(def ^:dynamic *stealth?* true)

(defmacro with-stealth
  [bool & body]
  (binding [*stealth?* ~bool]
    ~@body))
