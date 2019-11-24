(ns cryptohash-clj.equality)

(defn- ?nth
  [coll index]
  (try
    (nth coll index)
    ;; 0 is not even a printable char
    ;; so it can't possibly be part of the input
    (catch IndexOutOfBoundsException _ 0)))

(defn hash= ;; adapted from `crypto-equality`
  "Test whether two sequences of characters or bytes are equal in a way that
   protects against timing attacks. The comparison is done in linear-time wrt to
   <a> (the hashed input). However, the hashed input is always of fixed length,
   so the comparison is effectively in constant-time (per algorithm).
   No early aborting takes place."
  [a b]
  (let [a (some->> a not-empty (map int))
        b (some->> b not-empty (map int))]
    (or
      (and (nil? a)
           (nil? b))
      (and (some? a)
           (some? b)
           (->> a
                count
                range
                (map #(bit-xor
                        (?nth a %)
                        (?nth b %)))
                (reduce bit-or)
                zero?))
      false)))
