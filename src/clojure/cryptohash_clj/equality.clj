(ns cryptohash-clj.equality)

(defn hash= ;; adapted from `crypto-equality`
  "Test whether two sequences of characters or bytes are equal in a way that
   protects against timing attacks. Note that this does not prevent an attacker
   from discovering the *length* of the data being compared."
  [a b]
  (let [a (some->> a not-empty (mapv int))
        b (some->> b not-empty (mapv int))]
    (or
      (and (nil? a)
           (nil? b))
      (and (some? a)
           (some? b)
           (= (count a)
              (count b))
           (zero?
             (reduce bit-or (mapv bit-xor a b))))
      false)))
