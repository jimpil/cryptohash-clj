(ns cryptohash-clj.specs.pbkdf2
  (:require [clojure.spec.alpha :as s]))


(s/def ::algo
  #{:hmac+sha1 :hmac+sha256 :hmac+sha512})

(s/def ::key-length
  (s/and pos-int? #(zero? (rem % 8))))

(s/def ::salt-length
  pos-int?)

(s/def ::iterations
  pos-int?)

(s/def ::separator
  char?)

(s/def ::options
  (s/keys :opt-un [::algo ::key-length ::salt-length ::iterations ::separator]))
