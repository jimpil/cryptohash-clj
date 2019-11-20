(ns cryptohash-clj.equality)

(defn hash= ;; adopted from `crypto-equality`
  "Test whether two sequences of characters or bytes are equal in a way that
  protects against timing attacks. Note that this does not prevent an attacker
  from discovering the *length* of the data being compared."
  [a b]
  (let [a (seq (map int a))
        b (seq (map int b))]
    (or
      (and (nil? a)
           (nil? b))
      (and (some? a)
           (some? b)
           (= (count a) (count b))
           (zero? (reduce bit-or (map bit-xor a b))))
      false)))
