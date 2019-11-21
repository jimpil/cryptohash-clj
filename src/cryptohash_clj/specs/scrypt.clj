(ns cryptohash-clj.specs.scrypt
  (:require [clojure.spec.alpha :as s]))

(s/def ::cpu-cost
  pos-int?)

(s/def ::mem-cost
  pos-int?)

(s/def ::pfactor  ;; parallelisation factor
  pos-int?)

(s/def ::salt-length
  pos-int?)

(s/def ::options
  (s/keys :opt-un [::cpu-cost ::mem-cost ::pfactor ::salt-length]))
