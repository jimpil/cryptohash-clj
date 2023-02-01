(ns cryptohash-clj.api
  (:require [cryptohash-clj.impl
             [bcrypt :as b]
             [scrypt :as s]
             [pbkdf2 :as p]
             [argon2 :as a]]))

(defmulti hash-with (fn [k & _] k))

(defmethod hash-with :pbkdf2
  [_ raw & opts]
  (p/chash raw (first opts)))

(defmethod hash-with :bcrypt
  [_ raw & opts]
  (b/chash raw (first opts)))

(defmethod hash-with :scrypt
  [_ raw & opts]
  (s/chash raw (first opts)))

(defmethod hash-with :argon2
  [_ raw & opts]
  (a/chash raw (first opts)))

(defmulti verify-with (fn [k & _] k))

(defmethod verify-with :pbkdf2
  [_ raw hashed & opts]
  (p/verify raw hashed (first opts)))

(defmethod verify-with :bcrypt
  [_ raw hashed & opts]
  (b/verify raw hashed (first opts)))

(defmethod verify-with :scrypt
  [_ raw hashed & opts]
  (s/verify raw hashed (first opts)))

(defmethod verify-with :argon2
  [_ raw hashed & opts]
  (a/verify raw hashed (first opts)))
