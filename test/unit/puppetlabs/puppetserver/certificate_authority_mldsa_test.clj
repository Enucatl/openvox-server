(ns puppetlabs.puppetserver.certificate-authority-mldsa-test
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [puppetlabs.puppetserver.certificate-authority :as ca]
            [puppetlabs.ssl-utils.core :as utils]
            [schema.test :as schema-test])
  (:import (com.puppetlabs.ssl_utils SSLUtils)
           (java.security KeyPairGenerator Provider)
           (java.util Date)))

(use-fixtures :once schema-test/validate-schemas)

(deftest leaf-key-usage-matches-subject-key
  (let [provider ^Provider (.newInstance (SSLUtils/getProviderClass))
        ;; ML-DSA signing in this PoC requires Java 25 or configured BC providers.
        algorithms (cond-> [["RSA" nil #{:digital-signature :key-encipherment}]]
                     (and (not (SSLUtils/isFIPS))
                          (>= (Integer/parseInt (System/getProperty "java.specification.version")) 25))
                     (into [["ML-DSA-44" "SUN" #{:digital-signature}]
                            ["ML-DSA-44" provider #{:digital-signature}]]))
        settings (assoc (zipmap (keys ca/MasterSettings) (repeat ""))
                   :keylength 2048 :csr-attributes "/nonexistent-mldsa-csr-attributes.yaml")]
    (doseq [[algorithm key-provider expected] algorithms]
      (testing (str algorithm " / " key-provider)
        (let [keys (if key-provider
                     (.generateKeyPair (KeyPairGenerator/getInstance algorithm key-provider))
                     (utils/generate-key-pair 2048))
              public (.getPublic keys)
              private (.getPrivate keys)
              before (Date. (- (System/currentTimeMillis) 60000))
              after (Date. (+ (System/currentTimeMillis) 3600000))
              ca-cert (utils/sign-certificate "CN=issuer" private 1 before after "CN=issuer" public
                                             [(utils/basic-constraints-for-ca)
                                              (utils/key-usage #{:key-cert-sign :crl-sign} true)])
              csr (utils/generate-certificate-request keys "CN=leaf")]
          (doseq [[kind extensions] [[:agent (ca/create-agent-extensions csr ca-cert)]
                                    [:master (ca/create-master-extensions "leaf" public ca-cert settings)]]]
            (testing (name kind)
              (let [usage (first (filter #(= "2.5.29.15" (:oid %)) extensions))
                    certificate (utils/sign-certificate "CN=issuer" private 2 before after "CN=leaf" public extensions)]
                (is (= expected (:value usage)))
                (is (true? (:critical usage)))
                (is (= expected (utils/get-extension-value certificate "2.5.29.15")))
                (is (.contains (.getCriticalExtensionOIDs certificate) "2.5.29.15"))
                (is (nil? (.verify certificate public)))))))))))

(defn- issuer-test-settings [directory]
  {:access-control nil :allow-authorization-extensions false :allow-duplicate-certs false
   :allow-subject-alt-names false :allow-auto-renewal false :auto-renewal-cert-ttl 3600
   :allow-header-cert-info false :autosign true :ca-name "Printable CA" :ca-ttl 3600
   :keylength 2048 :manage-internal-file-permissions true :ruby-load-path [] :gem-path ""
   :cadir directory :cacert (str directory "/ca.pem") :cakey (str directory "/key.pem")
   :capub (str directory "/public.pem") :cacrl (str directory "/crl.pem")
   :cert-inventory (str directory "/inventory.txt") :serial (str directory "/serial")
   :csrdir (str directory "/requests") :signeddir (str directory "/signed")
   :infra-nodes-path (str directory "/infra-nodes") :infra-node-serials-path (str directory "/infra-serials")
   :infra-crl-path (str directory "/infra-crl.pem") :enable-infra-crl false
   :serial-lock (java.util.concurrent.locks.ReentrantReadWriteLock.) :serial-lock-timeout-seconds 5
   :crl-lock (java.util.concurrent.locks.ReentrantReadWriteLock.) :crl-lock-timeout-seconds 5
   :inventory-lock (java.util.concurrent.locks.ReentrantReadWriteLock.) :inventory-lock-timeout-seconds 5})

(deftest signing-and-renewal-preserve-ca-subject-der
  (doseq [algorithm (cond-> ["RSA"]
                     (and (not (SSLUtils/isFIPS))
                          (>= (Integer/parseInt (System/getProperty "java.specification.version")) 25))
                     (conj "ML-DSA-44"))]
    (testing algorithm
      (let [directory (.toFile (java.nio.file.Files/createTempDirectory
                                "issuer-der-" (make-array java.nio.file.attribute.FileAttribute 0)))
            settings (issuer-test-settings (str directory))
            keys (if (= algorithm "RSA") (utils/generate-key-pair 2048)
                   (.generateKeyPair (KeyPairGenerator/getInstance algorithm)))
            public (.getPublic keys)
            private (.getPrivate keys)
            issuer (-> (org.bouncycastle.asn1.x500.X500NameBuilder.)
                       (.addRDN org.bouncycastle.asn1.x500.style.BCStyle/CN
                                (org.bouncycastle.asn1.DERPrintableString. "Printable CA"))
                       (.build))
            builder (org.bouncycastle.cert.X509v3CertificateBuilder.
                      issuer (biginteger 1) (Date. (- (System/currentTimeMillis) 60000))
                      (Date. (+ (System/currentTimeMillis) 3600000)) issuer
                      (org.bouncycastle.asn1.x509.SubjectPublicKeyInfo/getInstance (.getEncoded public)))
            signer (.build (org.bouncycastle.operator.jcajce.JcaContentSignerBuilder.
                             (if (= algorithm "RSA") "SHA256withRSA" "ML-DSA-44")) private)
            ca-cert (.getCertificate (org.bouncycastle.cert.jcajce.JcaX509CertificateConverter.)
                                    (.build builder signer))
            csr (utils/generate-certificate-request keys "CN=leaf")]
        (try
          (.mkdir (java.io.File. (:csrdir settings)))
          (.mkdir (java.io.File. (:signeddir settings)))
          (ca/write-cert ca-cert (:cacert settings))
          (ca/write-private-key private (:cakey settings))
          (ca/initialize-serial-file! settings)
          (ca/autosign-certificate-request! "leaf" csr settings (constantly nil))
          (let [issued (utils/pem->cert (ca/path-to-cert (:signeddir settings) "leaf"))
                renewed (ca/renew-certificate! issued settings (constantly nil))]
            (doseq [certificate [issued renewed]]
              (is (= (seq (.getEncoded (.getSubjectX500Principal ca-cert)))
                     (seq (.getEncoded (.getIssuerX500Principal certificate)))))
              (is (nil? (.verify certificate public))))
            (is (< (.getSerialNumber issued) (.getSerialNumber renewed)))
            (is (= "CN=Printable CA" (utils/get-subject-from-x509-certificate ca-cert))))
          (finally
            (doseq [file (reverse (file-seq directory))] (.delete file))))))))
