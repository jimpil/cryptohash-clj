(ns cryptohash-clj.globals
  (:import [java.security SecureRandom]
           [java.util Random Arrays]))

(def ^:const SEP \$)
(def ^:const ^byte ZB (byte 0))

(def ^:dynamic ^Random *PRNG*
  (delay ;; static-initialiser with SecureRandom breaks GRAAL native-image
    (SecureRandom.)))

(defn next-random-bytes!
  ^bytes [n]
  (let [^bytes random-bs (byte-array n)]
    (.nextBytes ^Random (force *PRNG*) random-bs)
    random-bs))

(defmacro with-PRNG
  [prng & body]
  `(binding [*PRNG* ~prng]
     ~@body))

(def ^:dynamic *stealth?* true)

(defmacro with-stealth
  [bool & body]
  `(binding [*stealth?* ~bool]
     ~@body))

(defn fill-bytes!
  [& arys]
  (when *stealth?*
    (doseq [^bytes bs arys]
      (Arrays/fill bs ZB))))

(defn fill-chars!
  [& arys]
  (when *stealth?*
    (doseq [^chars cs arys]
      (Arrays/fill cs \u0000))))
