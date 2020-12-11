/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.securevault.hashicorp.repository;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.api.Logical;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.securevault.hashicorp.config.HashiCorpVaultConfigLoader;
import org.wso2.carbon.securevault.hashicorp.exception.HashiCorpVaultException;
import org.wso2.securevault.secret.SecretRepository;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.Properties;

import static org.wso2.carbon.securevault.hashicorp.common.HashiCorpVaultConstants.ADDRESS_PARAMETER;
import static org.wso2.carbon.securevault.hashicorp.common.HashiCorpVaultConstants.CARBON_HOME;
import static org.wso2.carbon.securevault.hashicorp.common.HashiCorpVaultConstants.DEFAULT_ENGINE_VERSION;
import static org.wso2.carbon.securevault.hashicorp.common.HashiCorpVaultConstants.ENGINE_PATH_PARAMETER;
import static org.wso2.carbon.securevault.hashicorp.common.HashiCorpVaultConstants.ENGINE_VERSION_PARAMETER;
import static org.wso2.carbon.securevault.hashicorp.common.HashiCorpVaultConstants.NAMESPACE_PARAMETER;
import static org.wso2.carbon.securevault.hashicorp.common.HashiCorpVaultConstants.VALUE_PARAMETER;

/**
 * HashiCorp Secret Repository.
 */
public class HashiCorpSecretRepository implements SecretRepository {

    private static final Log LOG = LogFactory.getLog(HashiCorpSecretRepository.class);
    private static final String SLASH = "/";

    private SecretRepository parentRepository;
    private String address;
    private String namespace;
    private String enginePath;
    private int engineVersion;

    private String textFileName;
    private String textFileName_tmp;
    private String textFilePersist;
    private boolean persistToken = false;
    private String rootToken;
    private static File tokenFile;
    private String PROPERTY_PREFIX = "secretProviders.vault.repositories.hashicorp.properties.";


    /**
     * Initializes the repository based on provided properties.
     *
     * @param properties Configuration properties
     * @param id         Identifier to identify properties related to the corresponding repository
     */
    @Override
    public void init(Properties properties, String id) {

        LOG.info("Initializing HashiCorp Secure Vault");

        // Load Configurations
        HashiCorpVaultConfigLoader hashiCorpVaultConfigLoader = HashiCorpVaultConfigLoader.getInstance();
        try {
            address = hashiCorpVaultConfigLoader.getProperty(PROPERTY_PREFIX + ADDRESS_PARAMETER);
            namespace = hashiCorpVaultConfigLoader.getProperty(PROPERTY_PREFIX + NAMESPACE_PARAMETER);
            enginePath = hashiCorpVaultConfigLoader.getProperty(PROPERTY_PREFIX + ENGINE_PATH_PARAMETER);

            String version = hashiCorpVaultConfigLoader.getProperty(PROPERTY_PREFIX + ENGINE_VERSION_PARAMETER);
            engineVersion = version != null ? Integer.parseInt(version) : DEFAULT_ENGINE_VERSION;
            // Get the vault token
            retrieveRootToken();
        } catch (HashiCorpVaultException e) {
            LOG.error(e.getMessage(), e);
        }

        if (rootToken == null || rootToken.isEmpty()) {
            LOG.warn("VAULT_TOKEN has not been provided.");
        }

        if (engineVersion != 2) {
            LOG.error("Supported engine version: 2");
        }
    }

    /**
     * Get Secret from the Secret Repository
     *
     * @param alias Alias name for look up a secret
     * @return Secret if there is any, otherwise, alias itself
     * @see SecretRepository
     */
    @Override
    public String getSecret(String alias) {

        if (StringUtils.isEmpty(alias)) {
            return alias;
        }

        StringBuilder sb = new StringBuilder()
                .append(enginePath)
                .append(SLASH)
                .append(alias);

        String secret = null;
        try {

            final VaultConfig config = new VaultConfig()
                    .address(address)
                    .token(rootToken)
                    .engineVersion(engineVersion)
                    .build();

            Vault vault = new Vault(config);
            Logical logical = vault.logical();
            if (namespace != null) {
                logical = logical.withNameSpace(namespace);
            }
            secret = logical.read(sb.toString()).getData()
                    .get(VALUE_PARAMETER);

            if (secret == null) {
                LOG.error("Cannot read the vault secret from the HashiCorp vault. " +
                        "Check whether the VAULT_TOKEN is correct and the secret path is available: " + sb.toString());
            }
        } catch (VaultException e) {
            LOG.error("Error while reading the vault secret value for key: " + sb.toString(), e);
        }

        return secret;
    }

    /**
     * Get Encrypted data.
     *
     * @param alias Alias of the secret
     * @return
     */
    @Override
    public String getEncryptedData(String alias) {

        throw new UnsupportedOperationException();
    }

    /**
     * Set parent repository.
     *
     * @param parent Parent secret repository
     */
    @Override
    public void setParent(SecretRepository parent) {

        this.parentRepository = parent;
    }

    /**
     * Get parent repository.
     *
     * @return
     */
    @Override
    public SecretRepository getParent() {

        return this.parentRepository;
    }

    /**
     * Get the root token of the vault. Either by prompting the user via the console or by accessing the text file
     * containing the root token.
     */
    private void retrieveRootToken() throws HashiCorpVaultException {

        String carbonHome = System.getProperty(CARBON_HOME);
        setTextFileName();

        if (new File(carbonHome + File.separator + textFilePersist).exists()) {
            persistToken = true;
        }

        tokenFile = new File(carbonHome + File.separator + textFileName);
        if (tokenFile.exists()) {
            rootToken = readToken(tokenFile);

            if (!persistToken) {
                if (!renameConfigFile(textFileName_tmp)) {
                    throw new HashiCorpVaultException("Error in renaming password config file.");
                }
            }
        } else {
            tokenFile = new File(carbonHome + File.separator + textFileName_tmp);
            if (tokenFile.exists()) {
                rootToken = readToken(tokenFile);

                if (!persistToken) {
                    if (deleteConfigFile()) {
                        throw new HashiCorpVaultException("Error in deleting password config file.");
                    }
                }
            } else {
                tokenFile = new File(carbonHome + File.separator + textFilePersist);
                if (tokenFile.exists()) {
                    rootToken = readToken(tokenFile);

                    if (!persistToken) {
                        if (deleteConfigFile()) {
                            throw new HashiCorpVaultException("Error in deleting password config file.");
                        }
                    }
                } else {
                    Console console;
                    char[] token;
                    if ((console = System.console()) != null && (token = console.readPassword("[%s]",
                            "Enter the Root Token: ")) != null) {
                        rootToken = String.valueOf(token);
                    }
                }
            }
        }
    }

    /**
     * Set the name for the text file which contains the root token.
     * For Linux: The file name should be hashicorpRootToken-tmp or hashicorpRootToken-persist.
     * For Windows: The file name should be hashicorpRootToken-tmp.txt or hashicorpRootToken-persist.txt.
     */
    private void setTextFileName() {

        String osName = System.getProperty("os.name");
        if (osName.toLowerCase().contains("win")) {
            textFileName = "hashicorpRootToken.txt";
            textFileName_tmp = "hashicorpRootToken-tmp.txt";
            textFilePersist = "hashicorpRootToken-persist.txt";
        } else {
            textFileName = "hashicorpRootToken";
            textFileName_tmp = "hashicorpRootToken-tmp";
            textFilePersist = "hashicorpRootToken-persist";
        }
    }

    /**
     * Util method to Read the root token from the text file.
     *
     * @param tokenFile File containing the root token.
     * @return The read token.
     * @throws HashiCorpVaultException when an error occurred while reading the root token.
     */
    private String readToken(File tokenFile) throws HashiCorpVaultException {

        String tokenReadFromFile;
        try (FileInputStream inputStream = new FileInputStream(tokenFile);
             BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream))) {
            tokenReadFromFile = bufferedReader.readLine();
        } catch (IOException e) {
            throw new HashiCorpVaultException("Error while reading the root token from " + tokenFile, e);
        }
        return tokenReadFromFile;
    }

    /**
     * Util method to rename the file containing root token.
     *
     * @param fileName Name of the text file.
     * @return true upon successful renaming.
     */
    private boolean renameConfigFile(String fileName) {

        if (tokenFile.exists()) {
            File newConfigFile = new File(System.getProperty(CARBON_HOME) + File.separator + fileName);
            return tokenFile.renameTo(newConfigFile);
        }
        return false;
    }

    /**
     * Util method to delete the temporary text file.
     *
     * @return true upon successful deletion.
     * @throws HashiCorpVaultException when an error occurred while deleting the root token file.
     */
    private boolean deleteConfigFile() throws HashiCorpVaultException {

        try (FileOutputStream outputStream = new FileOutputStream(tokenFile);
             BufferedWriter bufferedWriter = new BufferedWriter(new OutputStreamWriter(outputStream))) {
            bufferedWriter.write("!@#$%^&*()SDFGHJZXCVBNM!@#$%^&*");
        } catch (IOException e) {
            throw new HashiCorpVaultException("Error while deleting the " + tokenFile, e);
        }
        return !tokenFile.exists() || !tokenFile.delete();
    }

}
