(ns cryptohash-clj.specs.scrypt
  (:require [clojure.spec.alpha :as s]))

(s/def ::cpu-cost pos-int?) ;; 2^n where n => cpu-cost
(s/def ::mem-cost pos-int?)
(s/def ::pfactor  pos-int?)

(s/def ::options
  (s/keys :opt-un [::cpu-cost ::mem-cost ::pfactor]))
