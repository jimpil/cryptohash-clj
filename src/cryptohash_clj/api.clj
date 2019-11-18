(ns cryptohash-clj.api
  (:require [cryptohash-clj.impl
             [bcrypt :as b]
             [scrypt :as s]
             [pbkdf2 :as p]]))


(defmulti hash-with (fn [k raw opts] k))

(defmethod hash-with :pbkdf2
  [_ raw opts]
  (p/chash raw opts))

(defmethod hash-with :bcrypt
  [_ raw opts]
  (b/chash raw opts))

(defmethod hash-with :scrypt
  [_ raw opts]
  (s/chash raw opts))

(defmulti verify-with (fn [k raw opts hasled] k))

(defmethod verify-with :pbkdf2
  [_ raw opts hashed]
  (p/verify raw opts hashed))

(defmethod verify-with :bcrypt
  [_ raw opts hashed]
  (b/verify raw opts hashed))

(defmethod verify-with :scrypt
  [_ raw _ hashed]
  (s/verify raw hashed))