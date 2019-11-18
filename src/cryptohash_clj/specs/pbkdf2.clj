(ns cryptohash-clj.specs.pbkdf2
  (:require [clojure.spec.alpha :as s]))


(s/def ::algo #{:hmac-sha1 :hmac-sha256 :hmac-sha512})
(s/def ::key-length #(zero? (rem % 8)))
(s/def ::iterations int?)
(s/def ::separator  char?)

(s/def ::options
  (s/keys :opt-un [::algo ::key-length ::iterations ::separator]))
