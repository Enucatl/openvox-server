(require '[leiningen.core.project :as project])
(project/ensure-dynamic-classloader)
(def base (project/read "/build/project.clj" []))
(def artifact 'org.bouncycastle/bctls-jdk18on)
(doseq [[label profiles] [["dev" [:dev]] ["uberjar" [:uberjar]] ["ezbake" [:ezbake]]]]
  (let [effective (project/merge-profiles base profiles)]
    (assert (some #(= artifact (first %)) (:dependencies effective)) label)
    (assert (= "1.86.2" (second (first (filter #(= artifact (first %)) (:managed-dependencies effective))))) label)
    (println label "bctls" (filter #(= artifact (first %)) (:dependencies effective)))))
(let [fips (project/merge-profiles base [:fips :ezbake-fips :uberjar])
      class-name "org/bouncycastle/jsse/provider/BouncyCastleJsseProvider.class"
      installed (filter :install (get-in fips [:lein-ezbake :classpath-jars]))]
  (assert (some #(re-find % class-name) (:uberjar-exclusions fips)))
  (assert (= #{'org.bouncycastle/bc-fips 'org.bouncycastle/bcpkix-fips
               'org.bouncycastle/bctls-fips 'org.bouncycastle/bcutil-fips}
             (set (map :artifact installed))))
  (println "FIPS runtime excludes ordinary BC classes and installs only FIPS jars"))
(println "PROFILE_ASSERTIONS_PASS")
