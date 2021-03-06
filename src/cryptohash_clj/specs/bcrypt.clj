(ns cryptohash-clj.specs.bcrypt
  (:require [clojure.spec.alpha :as s]))


(s/def ::cpu-cost
  #(>= 31 % 4)) ;; 4-31 inclusive

(s/def ::version
  #{:v2a :v2b :v2y})

(s/def ::long-value
  #{:truncate :sha512})

(s/def ::options
  (s/keys :opt-un [::cpu-cost ::version ::long-value]))
