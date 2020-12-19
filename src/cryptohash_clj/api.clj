(ns cryptohash-clj.api
  (:require [cryptohash-clj.impl
             [bcrypt :as b]
             [scrypt :as s]
             [pbkdf2 :as p]
             [argon2 :as a]]))

(defmulti hash-with (fn [k & _] k))

(defmethod hash-with :pbkdf2
  [_ raw & opts]
  (apply p/chash raw opts))

(defmethod hash-with :bcrypt
  [_ raw & opts]
  (apply b/chash raw opts))

(defmethod hash-with :scrypt
  [_ raw & opts]
  (apply s/chash raw opts))

(defmethod hash-with :argon2
  [_ raw & opts]
  (apply a/chash raw opts))

(defmulti verify-with (fn [k & _] k))

(defmethod verify-with :pbkdf2
  [_ raw & args]
  (apply p/verify raw args))

(defmethod verify-with :bcrypt
  [_ raw & args]
  (apply b/verify raw args))

(defmethod verify-with :scrypt
  [_ raw & args]
  (apply s/verify raw args))

(defmethod verify-with :argon2
  [_ raw & args]
  (apply a/verify raw args))
