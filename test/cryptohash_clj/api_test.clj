(ns cryptohash-clj.api-test
  (:require [clojure.test :refer :all]
            [cryptohash-clj.api :refer :all]
            [cryptohash-clj.encode :as enc])
  (:import (org.bouncycastle.crypto.generators OpenBSDBCrypt)))

(defonce PASSWORD "_sUpErSeCrEt@1234!_")

(deftest hashing-roundtrip
  (testing "PBKDF2 with String input"
    (let [options {:iterations 100}
          hashed (hash-with :pbkdf2 PASSWORD options)]
      (is (string? hashed))
      (is (true? (verify-with :pbkdf2 PASSWORD options hashed))))
    )

  (testing "PBKDF2 with char-array input"
    (let [options {:iterations 100} ;; low cost on purpose
          hashed (hash-with :pbkdf2 (enc/to-chars PASSWORD) options)]
      (is (string? hashed))
      (is (true? (verify-with :pbkdf2 (enc/to-chars PASSWORD) options hashed))))
    )

  (testing "BCRYPT with String input"
    (let [options {:cpu-cost 4} ;; low cost on purpose
          hashed (hash-with :bcrypt PASSWORD options)]
      (is (string? hashed))
      (is (= 60 (count hashed)))
      (is (true? (verify-with :bcrypt PASSWORD options hashed))))
    )

  (testing "BCRYPT with char-array input"
    (let [options {:cpu-cost 4}
          hashed (hash-with :bcrypt (enc/to-chars PASSWORD) options)]
      (is (string? hashed))
      (is (= 60 (count hashed)))
      (is (true? (verify-with :bcrypt (enc/to-chars PASSWORD) options hashed)))
      ;; make sure we match the Java impl exactly!
      (is (true? (OpenBSDBCrypt/checkPassword hashed (enc/to-chars PASSWORD))))
      )
    )

  (testing "SCRYPT with String input"
         (let [options {:cpu-cost 2
                        :mem-cost 4} ;; low cost on purpose
               hashed (hash-with :scrypt PASSWORD options)]
           (is (string? hashed))
           (is (true? (verify-with :scrypt PASSWORD nil hashed))))
         )

  (testing "SCRYPT with char-array input"
    (let [options {:cpu-cost 2
                   :mem-cost 4} ;; low cost on purpose
          hashed (hash-with :scrypt (enc/to-chars PASSWORD) options)]
      (is (string? hashed))
      (is (true? (verify-with :scrypt (enc/to-chars PASSWORD) nil hashed))))
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
          hashed (hash-with :argon2 (enc/to-chars PASSWORD) options)]
      (is (string? hashed))
      (is (true? (verify-with :argon2 (enc/to-chars PASSWORD) nil hashed))))
    )
  )
