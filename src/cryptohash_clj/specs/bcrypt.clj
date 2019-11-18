(ns cryptohash-clj.specs.bcrypt
  (:require [clojure.spec.alpha :as s]))


(s/def ::cost (s/and int? (partial >= 31)))
(s/def ::version #{:v2a :v2b :v2x :v2y :v2y-no-null-terminator :vbc})
(s/def ::long-value-strategy #{:strict :truncate :sha512})

(s/def ::options
  (s/or
    :defaults #{:default}
    :opt-map (s/keys :opt-un [::cost ::version ::long-value-strategy])))
