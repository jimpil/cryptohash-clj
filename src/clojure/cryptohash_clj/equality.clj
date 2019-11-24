(ns cryptohash-clj.equality)

(defn hash= ;; adapted from `crypto-equality`
  "Test whether two sequences of characters/bytes are equal in a way that
   protects against timing attacks. Early aborting occurs if one/both
   arguments are nil (one => false,  both => true)."
  [a b]
  (let [a (some->> a not-empty (mapv int))
        b (some->> b not-empty (mapv int))]
    (or
      (and (nil? a)
           (nil? b)) ;; both nil => true
      (and (some? a) ;; one of them nil => false
           (some? b)
           (->> (map bit-xor a b) ;; assume lengths match
                (reduce bit-or)
                zero?)
           (= (count a) ;; confirm it in constant-time at the end
              (count b)))
      false)))
