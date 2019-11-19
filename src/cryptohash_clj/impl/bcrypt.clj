(ns cryptohash-clj.impl.bcrypt
  (:require [cryptohash-clj
             [proto :as proto]
             [random :as random]
             [util :as ut]])
  (:import [at.favre.lib.crypto.bcrypt BCrypt
                                       BCrypt$Version
                                       BCrypt$Hasher
                                       BCrypt$Verifyer
                                       LongPasswordStrategies
                                       LongPasswordStrategy]))

(defonce VERSIONS
  {:v2a BCrypt$Version/VERSION_2A
   :v2b BCrypt$Version/VERSION_2B
   :v2x BCrypt$Version/VERSION_2X
   :v2y BCrypt$Version/VERSION_2Y
   :v2y-nnt BCrypt$Version/VERSION_2Y_NO_NULL_TERMINATOR
   :vbc BCrypt$Version/VERSION_BC})

(defn- resolve-version
  ^BCrypt$Version [k]
  (or (get VERSIONS k)
      (throw
        (IllegalArgumentException.
          (format "BCrypt version %s not supported..." k)))))

(defn- resolve-strategy
  ^LongPasswordStrategy
  [strategy ^BCrypt$Version v]
  (case strategy
    :strict   (LongPasswordStrategies/strict v)
    :truncate (LongPasswordStrategies/truncate v)
    :sha512   (LongPasswordStrategies/hashSha512 v)))


(declare new-hasher)
(defn- bcrypt*
  [input ;; chars or bytes
   {:keys [cpu-cost hasher]
    :or {cpu-cost 12} ;; less than 12 is not safe in 2019
    :as opts}
   f]
  (f (or hasher
         (new-hasher opts))
       cpu-cost
       input))

(defn- to-chars
  ^chars [^BCrypt$Hasher h cost ^chars x]
  (.hashToChar h cost x))

(defn- to-string
  ^String [^BCrypt$Hasher h cost ^chars x]
  (.hashToString h cost x))

(defn- to-bytes
  ^bytes [^BCrypt$Hasher h ^long cost ^bytes x]
  (.hash h cost x))

(declare new-verifyer)
(defmacro ^:private hash= ;; has to be a macro to avoid reflection
  [raw-chars opts encrypted]
  `(let [opts# ~opts
         ^BCrypt$Verifyer verifyer# (or (:verifyer opts#)
                                        (new-verifyer opts#))]
     (-> verifyer#
         (.verify ~raw-chars ~encrypted)
         .verified)))

(extend-protocol proto/IHashable

  (Class/forName "[C") ;; char-arrays
  (proto/chash [this opts]
    (bcrypt* this opts to-chars))
  (proto/verify [this opts hashed]
    (hash= ^chars this opts ^chars hashed))

  String
  (proto/chash [this opts]
    (bcrypt* (.toCharArray this) opts to-string))
  (proto/verify [this opts hashed]
    (hash= (.toCharArray this) opts ^String hashed))
  )

(extend-protocol proto/IHashable
  (Class/forName "[B") ;; byte-arrays
  (proto/chash [this opts]
    (bcrypt* this opts to-bytes))
  (proto/verify [this opts hashed]
    (hash= (ut/bytes->chars this) opts ^bytes hashed)))
;;=======================================================

(defn new-hasher
  "Returns a BCrypt hasher object with the given version (see `VERSIONS`),
   and strategy (:strict/:truncate/:sha512 - applicable for values larger
   than 72 bytes). Can be reused via the :hasher option key (see `chash*`)."
  ^BCrypt$Hasher
  [opts]
  (if (= :default opts)
    (BCrypt/withDefaults)
    (let [{:keys [version long-value-strategy]
           :or {version :v2a
                long-value-strategy :sha512}} opts
          ^BCrypt$Version v (resolve-version version)
          strategy (resolve-strategy long-value-strategy v)]
      (BCrypt/with v random/*PRNG* strategy))))

(defn new-verifyer
  ^BCrypt$Verifyer
  [opts]
  (if (= :default opts)
    (BCrypt/verifyer)
    (let [{:keys [version long-value-strategy]
           :or {version :v2a
                long-value-strategy :sha512}} opts
          v (resolve-version version)
          strategy (resolve-strategy long-value-strategy v)]
      (BCrypt/verifyer v strategy))))

(defn chash
  "Main entry point for hashing <x> (String/bytes/chars) using BCrypt.
   <opts> must inlude a :cost key and either a pre-constructed :hasher,
   or options per `new-hasher`. The return value type is dictated by <x>."
  [x opts]
  (proto/chash x opts))

(defn verify
  "Main entry point for verifying that <x> (String/bytes/chars) matches <hashed>.
   <opts> must match the ones used to produce <hashed> and can include a
   pre-constructed :verifyer. Returns true/false."
  [x opts hashed]
  (proto/verify x opts (ut/to-str hashed)))
