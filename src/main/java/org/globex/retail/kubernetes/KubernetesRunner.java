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

        String keystoreType = System.getenv().getOrDefault("KEYSTORE_TYPE", "JKS");

        String keystorePassword = System.getenv().getOrDefault("KEYSTORE_PASSWD", "password");

        String keystoreName = System.getenv().getOrDefault("KEYSTORE_NAME", "client-infinispan.ts");

        String keystoreAlias = System.getenv().getOrDefault("KEYSTORE_ALIAS", "infinispan");

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
            KeyStore ks = KeyStore.getInstance(keystoreType);
            char[] pwdArray = keystorePassword.toCharArray();
            ks.load(null, pwdArray);

            InputStream is = new ByteArrayInputStream(certDecoded);
            Certificate cert = CertificateFactory.getInstance("X509").generateCertificate(is);

            ks.setCertificateEntry(keystoreAlias, cert);

            // Save the keyStore
            FileOutputStream fos = new FileOutputStream("/tmp/" + keystoreName);
            ks.store(fos, pwdArray);
            fos.close();

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ks.store(bos, pwdArray);
            bos.close();

            ksBytes = bos.toByteArray();

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            LOGGER.error("Error when creating keystore. Exiting.", e);
            return -1;
        }

        // create secret
        String clientProperties = "infinispan.client.hotrod.trust_store_file_name = classpath:" + keystoreName + "\n" +
                "infinispan.client.hotrod.trust_store_password = " + keystorePassword;

        Secret clientSecret = new SecretBuilder().withNewMetadata().withName(clientSecretName).endMetadata().withType("Opaque")
                .addToData(keystoreName, Base64.getEncoder().encodeToString(ksBytes))
                .addToData(clientPropertiesName, Base64.getEncoder().encodeToString(clientProperties.getBytes()))
                .build();

        client.secrets().inNamespace(namespace).resource(clientSecret).createOrReplace();

        LOGGER.info("Secret " + clientSecretName + " created. Exiting.");

        return 0;

    }

}
