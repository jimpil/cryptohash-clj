(ns cryptohash-clj.specs.argon2
  (:require [clojure.spec.alpha :as s]))

(s/def ::type
  #{:argon2d :argon2i :argon2id})

(s/def ::version
  #{:v10 :v13})

(s/def ::iterations
  pos-int?)

(s/def ::mem-cost
  pos-int?)

(s/def ::pfactor  ;; parallelisation factor
  pos-int?)

(s/def ::key-length ;; in bytes
  pos-int?)

(s/def ::salt-length ;; in bytes
  pos-int?)

(s/def ::additional
  bytes?)

(s/def ::secret
  bytes?)

(s/def ::options
  (s/keys :opt-un [::type
                   ::version
                   ::iterations
                   ::mem-cost
                   ::pfactor
                   ::key-length
                   ::salt-length
                   ::additional
                   ::secret]))
