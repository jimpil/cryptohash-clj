(ns cryptohash-clj.cli.tool
  (:refer-clojure :exclude [parse-opts])
  (:require [clojure.tools.cli :refer [parse-opts]]
            [cryptohash-clj.api :as api]
            [clojure.edn :as edn])
  (:gen-class))


(def hashers
  #{:pbkdf2 :bcrypt :scrypt :argon2})

(defn- ?map?
  [x]
  (or (nil? x)
      (map? x)))

(def cli-options

  [["-f" "--function FUNCTION" "Hashing function"
    :default :bcrypt
    :parse-fn keyword
    :validate [hashers (str "Must be one of " (mapv name hashers))]]

   ["-i" "--input INPUT"  "Raw value"
    :validate [not-empty "Cannot be empty"]]

   ["-o" "--opts OPTIONS" "Options map"
    :parse-fn #(some-> % edn/read-string)
    :validate [?map? "Must be a Clojure map"]]

   ;; A boolean option defaulting to nil
   ["-h" "--help"]])

(defn -main
  [& args]
  (let [{:keys [options summary errors]}
        (parse-opts args cli-options)]
    (if errors
      (doseq [er errors] (println er))
      (let [{:keys [function input opts help]} options]
        (println
          (if help
            summary
            (api/hash-with function input opts)))))))
