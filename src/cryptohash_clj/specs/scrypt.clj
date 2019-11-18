(ns cryptohash-clj.specs.scrypt
  (:require [clojure.spec.alpha :as s]))

(s/def ::cpu-cost int?)
(s/def ::mem-cost int?)
(s/def ::pfactor  int?)

(s/def ::options
  (s/keys :opt-un [::cpu-cost ::mem-cost ::pfactor]))
