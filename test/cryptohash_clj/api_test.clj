(ns cryptohash-clj.api-test
  (:require [clojure.test :refer :all]
            [cryptohash-clj.api :refer :all]
            [cryptohash-clj.encode :as enc])
  (:import (org.bouncycastle.crypto.generators OpenBSDBCrypt)))

(defonce PASSWORD "_sUpErSeCrEt@1234!_")

(deftest roundtrip-with-defaults

  (testing "PBKDF2 with String input"
    (let [hashed (hash-with :pbkdf2 PASSWORD)]
      (is (string? hashed))
      (is (true? (verify-with :pbkdf2 PASSWORD hashed))))
    )

  (testing "PBKDF2 with char-array input"
    (let [hashed (hash-with :pbkdf2 (enc/to-chars PASSWORD))]
      (is (string? hashed))
      (is (true? (verify-with :pbkdf2 (enc/to-chars PASSWORD) hashed))))
    )

  (testing "PBKDF2 with byte-array input"
    (let [hashed (hash-with :pbkdf2 (enc/to-bytes PASSWORD))]
      (is (string? hashed))
      (is (true? (verify-with :pbkdf2 (enc/to-bytes PASSWORD) hashed))))
    )

  (testing "BCRYPT with String input"
    (let [hashed (hash-with :bcrypt PASSWORD)]
      (is (string? hashed))
      (is (= 60 (count hashed)))
      (is (true? (verify-with :bcrypt PASSWORD hashed))))
    )

  (testing "BCRYPT with char-array input"
    (let [hashed (hash-with :bcrypt (enc/to-chars PASSWORD))]
      (is (string? hashed))
      (is (= 60 (count hashed)))
      (is (true? (verify-with :bcrypt (enc/to-chars PASSWORD) hashed)))
      ;; make sure we match the Java impl exactly!
      (is (true? (OpenBSDBCrypt/checkPassword hashed (enc/to-chars PASSWORD))))
      )
    )

  (testing "BCRYPT with byte-array input"
    (let [hashed (hash-with :bcrypt (enc/to-bytes PASSWORD) nil)]
      (is (string? hashed))
      (is (= 60 (count hashed)))
      (is (true? (verify-with :bcrypt (enc/to-bytes PASSWORD) nil hashed))))
    )

  (testing "SCRYPT with String input"
    (let [hashed (hash-with :scrypt PASSWORD)]
      (is (string? hashed))
      (is (true? (verify-with :scrypt PASSWORD hashed))))
    )

  (testing "SCRYPT with char-array input"
    (let [hashed (hash-with :scrypt (enc/to-chars PASSWORD))]
      (is (string? hashed))
      (is (true? (verify-with :scrypt (enc/to-chars PASSWORD) hashed))))
    )

  (testing "SCRYPT with byte-array input"
    (let [hashed (hash-with :scrypt (enc/to-bytes PASSWORD))]
      (is (string? hashed))
      (is (true? (verify-with :scrypt (enc/to-bytes PASSWORD) hashed))))
    )

  (testing "ARGON2 with String input"
    (let [hashed (hash-with :argon2 PASSWORD)]
      (is (string? hashed))
      (is (true? (verify-with :argon2 PASSWORD hashed))))
    )

  (testing "ARGON2 with char-array input"
    (let [hashed (hash-with :argon2 (enc/to-chars PASSWORD))]
      (is (string? hashed))
      (is (true? (verify-with :argon2 (enc/to-chars PASSWORD) hashed))))
    )

  (testing "ARGON2 with byte-array input"
    (let [hashed (hash-with :argon2 (enc/to-bytes PASSWORD))]
      (is (string? hashed))
      (is (true? (verify-with :argon2 (enc/to-bytes PASSWORD) hashed))))
    )
  )
