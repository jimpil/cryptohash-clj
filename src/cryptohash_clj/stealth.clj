(ns cryptohash-clj.stealth)

(def ^:dynamic *stealth?* true)

(defmacro with-stealth
  [bool & body]
  (binding [*stealth?* ~bool]
    ~@body))
