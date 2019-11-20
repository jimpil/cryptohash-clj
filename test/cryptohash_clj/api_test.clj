(ns cryptohash-clj.api-test
  (:require [clojure.test :refer :all]
            [cryptohash-clj.api :refer :all]
            [cryptohash-clj.util :as ut]))

(defonce PASSWORD "_sUpErSeCrEt@1234!_")

(deftest hashing-roundtrip
  (testing "PBKDF2 with String input"
    (let [options {:iterations 100}
          hashed (hash-with :pbkdf2 PASSWORD options)]
      (is (string? hashed))
      (is (true? (verify-with :pbkdf2 PASSWORD options hashed))))
    )

  (testing "PBKDF2 with char-array input"
    (let [options {:iterations 1000} ;; low cost on purpose
          hashed (hash-with :pbkdf2 (.toCharArray PASSWORD) options)]
      (is (string? hashed))
      (is (true? (verify-with :pbkdf2 (.toCharArray PASSWORD) options hashed))))
    )

  (testing "BCRYPT with String input"
    (let [options {:cpu-cost 6} ;; low cost on purpose
          hashed (hash-with :bcrypt PASSWORD options)]
      (is (string? hashed))
      (is (true? (verify-with :bcrypt PASSWORD options hashed))))
    )

  (testing "BCRYPT with char-array input"
    (let [options {:cpu-cost 7}
          hashed (hash-with :bcrypt (.toCharArray PASSWORD) options)]
      (is (string? hashed))
      (is (true? (verify-with :bcrypt (.toCharArray PASSWORD) options hashed))))
    )

  (testing "SCRYPT with String input"
         (let [options {:cpu-cost 7
                        :mem-cost 4} ;; low cost on purpose
               hashed (hash-with :scrypt PASSWORD options)]
           (is (string? hashed))
           (is (true? (verify-with :scrypt PASSWORD nil hashed))))
         )

  (testing "SCRYPT with char-array input"
    (let [options {:cpu-cost 7
                   :mem-cost 4} ;; low cost on purpose
          hashed (hash-with :scrypt (.toCharArray PASSWORD) options)]
      (is (string? hashed))
      (is (true? (verify-with :scrypt (.toCharArray PASSWORD) nil hashed))))
    )

  (testing "ARGON2 with String input"
    (let [options {:iterations 2
                   :mem-cost 4} ;; low cost on purpose
          hashed (hash-with :argon2 PASSWORD options)]
      (is (string? hashed))
      (is (true? (verify-with :argon2 PASSWORD nil hashed))))
    )

  (testing "ARGON2 with char-array input"
    (let [options {:iterations 2
                   :mem-cost 4} ;; low cost on purpose
          hashed (hash-with :argon2 (.toCharArray PASSWORD) options)]
      (is (string? hashed))
      (is (true? (verify-with :argon2 (.toCharArray PASSWORD) nil hashed))))
    )
  )
