(ns cryptohash-clj.api-test
  (:require [clojure.test :refer :all]
            [cryptohash-clj.api :refer :all]))

(defonce PASSWORD "_sUpErSeCrEt@1234!_")

(deftest hashing-roundtrip
  (testing "PBKDF2 with String input"
    (let [options {:iterations 100}
          hashed (hash-with :pbkdf2 PASSWORD options)]
      (is (true? (verify-with :pbkdf2 PASSWORD options hashed))))
    )

  (testing "PBKDF2 with char-array input"
    (let [options {:iterations 100} ;; low cost on purpose
          hashed (hash-with :pbkdf2 (.toCharArray PASSWORD) options)]
      (is (true? (verify-with :pbkdf2 (.toCharArray PASSWORD) options (apply str hashed)))))
    )

  (testing "BCRYPT with String input"
    (let [options {:cost 2} ;; low cost on purpose
          hashed (hash-with :bcrypt PASSWORD options)]
      (is (true? (verify-with :bcrypt PASSWORD options hashed))))
    )

  (testing "BCRYPT with char-array input"
    (let [options {:cost 2}
          hashed (hash-with :bcrypt (.toCharArray PASSWORD) options)]
      (is (true? (verify-with :bcrypt (.toCharArray PASSWORD) options (apply str hashed)))))
    )

  (testing "SCRYPT with String input"
    (let [options {:cpu-cost 16
                   :mem-cost 4} ;; low cost on purpose
          hashed (hash-with :scrypt PASSWORD options)]
      (is (true? (verify-with :scrypt PASSWORD nil hashed))))
    )
  )
