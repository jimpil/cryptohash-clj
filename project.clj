(defproject cryptohash-clj "0.1.4-SNAPSHOT"
  :description "Cryptographic hashing facilities (pbkdf2/bcrypt/scrypt/argon2) for Clojure"
  :url "https://github.com/jimpil/cryptohash-clj"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}

  :dependencies [[org.clojure/clojure "1.10.1" :scope "provided"]
                 [org.bouncycastle/bcpkix-jdk15on "1.64"]]

  :javac-options ["--release" "8"]
  :release-tasks [["vcs" "assert-committed"]
                  ["change" "version" "leiningen.release/bump-version" "release"]
                  ["vcs" "commit"]
                  ["vcs" "tag" "--no-sign"]
                  ["deploy"]
                  ["change" "version" "leiningen.release/bump-version"]
                  ["vcs" "commit"]
                  ;["vcs" "push"]
                  ]
  :deploy-repositories [["releases" :clojars]] ;; lein release :patch
  :signing {:gpg-key "jimpil1985@gmail.com"}
  :repl-options {:init-ns cryptohash-clj.api})
