(defproject cryptohash-clj "0.1.7"
  :description "Cryptographic hashing facilities (pbkdf2/bcrypt/scrypt/argon2) for Clojure"
  :url "https://github.com/jimpil/cryptohash-clj"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}

  :dependencies [[org.clojure/clojure "1.10.1" :scope "provided"]
                 ;[org.clojure/clojure "1.9.0"] ;; for native-image
                 [org.bouncycastle/bcpkix-jdk15on "1.67"]]

  :profiles {:dev {:dependencies [[org.clojure/tools.cli "0.4.2"]]}
             :uberjar {:aot :all
                       :main cryptohash-clj.cli.tool
                       :jar-exclusions []
                       :uberjar-name "cryptohash.jar"
                       :jvm-opts ["-Dclojure.compiler.direct-linking=true"]
                       :dependencies [[org.clojure/tools.cli "0.4.2"]]
                       }}

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
  :repl-options {:init-ns cryptohash-clj.api}

  ;; CLI tool
  :plugins [[io.taylorwood/lein-native-image "0.3.1"]]
  :native-image {;; name of output image, optional
                 :name "cryptohash"
                 ;; path to GraalVM home, optional
                 :graal-bin
                        "/Library/Java/JavaVirtualMachines/graalvm-ce-java11-19.3.0/Contents/Home/bin"
                         ;"/home/dimitris/graalvm-ce-java11-19.3.0/bin"

                 ;; pass-thru args to GraalVM native-image, optional
                 :opts ["--verbose"
                        "--no-fallback"
                        "--enable-all-security-services"
                        "--initialize-at-build-time"
                        ;"--initialize-at-run-time='cryptohash_clj.globals$next_random_bytes_BANG_',clojure.lang.Var"
                        ;"--rerun-class-initialization-at-runtime='sun.security.jca.JCAUtil$CachedSecureRandomHolder',java.security.SecureRandom"
                        "-H:+ReportExceptionStackTraces"
                        "--report-unsupported-elements-at-runtime"]
                 :jvm-opts ["-Dclojure.compiler.direct-linking=true"]}

  ;:main cryptohash-clj.cli.tool
  :jar-exclusions [#"tool.clj"]
  )
