(defproject cryptohash-clj "0.1.4-SNAPSHOT"
  :description "Cryptographic hashing (pbkdf2/bcrypt/scrypt) for Clojure"
  :url "https://github.com/jimpil/cryptohash-clj"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.10.1" :scope "provided"]
                 [at.favre.lib/bcrypt "0.9.0"]
                 [com.lambdaworks/scrypt "1.4.0"]]

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
