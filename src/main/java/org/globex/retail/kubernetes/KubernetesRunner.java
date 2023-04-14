package org.globex.retail.kubernetes;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.dsl.Resource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

@ApplicationScoped
public class KubernetesRunner {

    private static final Logger LOGGER = LoggerFactory.getLogger(KubernetesRunner.class);

    @Inject
    KubernetesClient client;

    public int run() {

        String datagridCrName = System.getenv("DATAGRID_CR_NAME");
        if (datagridCrName == null || datagridCrName.isBlank()) {
            LOGGER.error("Environment variable 'DATAGRID_CR_NAME' for deployment not set. Exiting...");
            return -1;
        }

        String namespace = System.getenv("NAMESPACE");
        if (namespace == null || namespace.isBlank()) {
            LOGGER.error("Environment variable 'NAMESPACE' for namespace not set. Exiting...");
            return -1;
        }

        String certificateName = System.getenv().getOrDefault("DATAGRID_CERTIFICATE_NAME", "tls.crt");

        String truststoreType = System.getenv().getOrDefault("TRUSTSTORE_TYPE", "JKS");

        String truststorePassword = System.getenv().getOrDefault("TRUSTSTORE_PASSWD", "password");

        String truststoreName = System.getenv().getOrDefault("TRUSTSTORE_NAME", "client-infinispan.ts");

        String truststoreAlias = System.getenv().getOrDefault("TRUSTSTORE_ALIAS", "infinispan");

        String saslMechanism = System.getenv().getOrDefault("SASL_MECHANISM", "SCRAM-SHA-512");

        String username = System.getenv().getOrDefault("DATAGRID_USERNAME", "developer");

        String password = System.getenv().getOrDefault("DATAGRID_PASSWORD", "password");

        String clientSecretName = System.getenv().getOrDefault("DATAGRID_CLIENT_SECRET", "client-infinispan");

        String clientPropertiesName = System.getenv().getOrDefault("DATAGRID_CLIENT_PROPERTIES", "infinispan.properties");

        String maxTimeToWaitStr = System.getenv().getOrDefault("MAX_TIME_TO_WAIT_MS", "300000");

        long maxTimeToWait = Long.parseLong(maxTimeToWaitStr);

        // Wait for datagrid ca secret
        String secretName = datagridCrName + "-cert-secret";
        Resource<Secret> certSecret = client.secrets().inNamespace(namespace).withName(secretName);

        try {
            certSecret.waitUntilCondition(Objects::nonNull, maxTimeToWait, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            LOGGER.error("Secret " + secretName + " is not available after " + maxTimeToWaitStr + " milliseconds. Exiting...");
            return -1;
        }

        if (certSecret.get() == null) {
            LOGGER.error("Secret " + secretName + " is not available after " + maxTimeToWaitStr + " milliseconds. Exiting...");
            return -1;
        }

        // Extract certificate from secret
        String certEncoded = certSecret.get().getData().get("tls.crt");
        if (certEncoded == null || certEncoded.isBlank()) {
            LOGGER.error("Secret " + secretName + " does not contain a certificate with name " + certificateName + " Exiting...");
            return -1;
        }

        byte[] certDecoded = Base64.getDecoder().decode(certEncoded);

        // build keystore
        byte[] ksBytes;
        try {
            KeyStore ks = KeyStore.getInstance(truststoreType);
            char[] pwdArray = truststorePassword.toCharArray();
            ks.load(null, pwdArray);

            InputStream is = new ByteArrayInputStream(certDecoded);
            Certificate cert = CertificateFactory.getInstance("X509").generateCertificate(is);

            ks.setCertificateEntry(truststoreAlias, cert);

            // Save the keyStore a a byte array
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ks.store(bos, pwdArray);
            bos.close();

            ksBytes = bos.toByteArray();

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            LOGGER.error("Error when creating keystore. Exiting.", e);
            return -1;
        }

        // create secret
        String clientProperties = """
                infinispan.client.hotrod.use_ssl = true
                infinispan.client.hotrod.trust_store_file_name = classpath:%s
                infinispan.client.hotrod.trust_store_password = %s
                infinispan.client.hotrod.trust_store_type = %s
                
                infinispan.client.hotrod.sasl_mechanism = %s
                infinispan.client.hotrod.auth_username = %s
                infinispan.client.hotrod.auth_password = %s                
                """.formatted(truststoreName, truststorePassword, truststoreType, saslMechanism, username, password);

        Secret clientSecret = new SecretBuilder().withNewMetadata().withName(clientSecretName).endMetadata().withType("Opaque")
                .addToData(truststoreName, Base64.getEncoder().encodeToString(ksBytes))
                .addToData(clientPropertiesName, Base64.getEncoder().encodeToString(clientProperties.getBytes()))
                .build();

        client.secrets().inNamespace(namespace).resource(clientSecret).createOrReplace();

        LOGGER.info("Secret " + clientSecretName + " created. Exiting.");

        return 0;

    }

}
