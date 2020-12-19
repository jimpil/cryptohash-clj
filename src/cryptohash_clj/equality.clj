(ns cryptohash-clj.equality)

(defn hash= ;; adapted from `crypto-equality`
  "Test whether two sequences of characters/bytes are equal in a way that
   protects against timing attacks. Early aborting occurs if one/both
   arguments are nil (one => false,  both => true), or if the sequences
   are found to be of different lengths. Note that, the latter can allow
   an attacker to discover the length of the data being compared.
   However, in the context of crypto-hashing this is not a concern as the
   length of a key is typically not considered to be a secret
   (e.g. BCrypt & the entire SHA family have well-known/fixed key lengths)."
  [a b]
  (let [a (some->> a not-empty (map int))
        b (some->> b not-empty (map int))]
    (or
      (and (nil? a)
           (nil? b)) ;; both nil => true
      (and (some? a) ;; one of them nil => false
           (some? b)
           (= (count a)
              (count b)) ;; ensure equal lengths before comparison
           (->> (map bit-xor a b)
                (reduce bit-or)
                zero?))
      false)))
