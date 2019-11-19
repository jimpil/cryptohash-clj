(ns cryptohash-clj.specs.bcrypt
  (:require [clojure.spec.alpha :as s]))


(s/def ::cpu-cost
  pos-int?) ;; 2^n where n => cost

(s/def ::version
  #{:v2a :v2b :v2x :v2y :v2y-nnt :vbc})

(s/def ::long-value-strategy
  #{:strict :truncate :sha512})

(s/def ::options
  (s/or
    :defaults #{:default}
    :opt-map (s/keys :opt-un [::cpu-cost ::version ::long-value-strategy])))
