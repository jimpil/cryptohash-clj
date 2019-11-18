(ns cryptohash-clj.api
  (:require [cryptohash-clj.impl
             [bcrypt :as b]
             [scrypt :as s]
             [pbkdf2 :as p]]
            [cryptohash-clj.specs
             [bcrypt :as bs]
             [scrypt :as ss]
             [pbkdf2 :as ps]]
            [clojure.spec.alpha :as sp]))

(defn- validate-options!
  [opts spec]
  (when-let [errors (sp/explain-data spec opts)]
    (throw (ex-info "Invalid options detected!" errors))))


(defmulti hash-with (fn [k raw opts] k))

(defmethod hash-with :pbkdf2
  [_ raw opts]
  (validate-options! opts ::ps/options)
  (p/chash raw opts))

(defmethod hash-with :bcrypt
  [_ raw opts]
  (validate-options! opts ::bs/options)
  (b/chash raw opts))

(defmethod hash-with :scrypt
  [_ raw opts]
  (validate-options! opts ::ss/options)
  (s/chash raw opts))

(defmulti verify-with (fn [k raw opts hasled] k))

(defmethod verify-with :pbkdf2
  [_ raw opts hashed]
  (validate-options! opts ::ps/options)
  (p/verify raw opts hashed))

(defmethod verify-with :bcrypt
  [_ raw opts hashed]
  (validate-options! opts ::bs/options)
  (b/verify raw opts hashed))

(defmethod verify-with :scrypt
  [_ raw _ hashed]
  (s/verify raw hashed))