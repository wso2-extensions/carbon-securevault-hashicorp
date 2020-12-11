# Intergrate HashiCorp Vault with WSO2 Identity Server

## Overview
This is another version of Hashicorp Vault Connector which is compatible with the External Vault Support.
In order to use this version, it is required to have WSO2 Identity Server 5.12.0 or above. Any version lesser than
WSO2 Identity Server 5.12.0 would have to use the [version-1](https://github.com/wso2-extensions/carbon-securevault-hashicorp.git)

## Setting up

### Step 1: Setup HashiCorp Vault

1. Start HashiCorp vault server and create a new **kv engine**.

   Enter a Path name when creating the kv engine (Eg: `wso2is`).
  
   Following commands can be used to add secrets with the HashiCorp vault.
   
   ```
   # Create a new kv engine
   vault secrets enable -path=wso2is -version=2 kv
   
   # Add new secret
   vault kv put wso2is/keystore_password value=wso2carbon
   
   # Get a secret (To check)
   vault kv get -field=value wso2is/keystore_password
   ```

### Step 2: Configure HashiCorp Vault extension

1. Build the HashiCorp Vault Integration OSGI bundle using `mvn clean install` and copy
the `target/org.wso2.carbon.securevault.hashicorp-2.0.0.jar` file to `<IS_HOME>/repository/components/dropin/`
directory.

2. Add **HashiCorp Vault Java Driver** (Eg: `vault-java-driver-5.1.0.jar`) to the
`<IS_HOME>/repository/components/lib/` directory.

3. Open `/repository/conf/security/secret-conf.properties` file and set following configurations.
    ```
    carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler
    
    secretProviders = vault
    secretProviders.vault.provider=org.wso2.securevault.secret.repository.VaultSecretRepositoryProvider
    
    secretProviders.vault.repositories=hashicorp
    secretProviders.vault.repositories.hashicorp=org.wso2.carbon.securevault.hashicorp.repository.HashiCorpSecretRepository 
    
    secretProviders.vault.repositories.hashicorp.properties.address=https://127.0.0.1:8200
    secretProviders.vault.repositories.hashicorp.properties.namespace=ns1
    secretProviders.vault.repositories.hashicorp.properties.enginePath=wso2is
    secretProviders.vault.repositories.hashicorp.properties.engineVersion=2
    ```

    **Note:** In production, you should always use the vault address with TLS enabled.

4. Add following lines to the `<IS_HOME>/repository/conf/log4j2.properties` file
    ```
    logger.org-wso2-carbon-securevault-hashicorp.name=org.wso2.carbon.securevault.hashicorp
    logger.org-wso2-carbon-securevault-hashicorp.level=INFO
    logger.org-wso2-carbon-securevault-hashicorp.additivity=false
    logger.org-wso2-carbon-securevault-hashicorp.appenderRef.CARBON_CONSOLE.ref = CARBON_CONSOLE
    ```
   Then append `org-wso2-carbon-securevault-hashicorp` to the `loggers` list in the same file as follows.
   ```
   loggers = AUDIT_LOG, trace-messages, ... , org-wso2-carbon-securevault-hashicorp
   ```

### Step 3: Update passwords with their aliases
1. Open the `deployment.toml` file in the `<IS_HOME>/repository/conf/` directory and add
   the `[runtime_secrets]` configuration property as shown below.

    ```toml
    [runtime_secrets]
    enable = "true"
    ```
   
2. Add the encrypted password alias to the relevant sections in the `deployment.toml`
   file by using a place holder: `$secret{alias}`. For example:

    ```toml
    [super_admin]
    username="admin"
    password="$secret{admin_password}"
    
    [keystore.primary]
    file_name = "wso2carbon.jks"
    password = "$secret{keystore_password}" 
    
    [database.identity_db]
    type = "h2"
    url = "jdbc:h2:./repository/database/WSO2IDENTITY_DB;DB_CLOSE_ON_EXIT=FALSE;LOCK_TIMEOUT=60000"
    username = "wso2carbon"
    password = "$secret{database_password}"
    ```
   NOTE: When there are multiple secret repositories configured (other than Hashicorp vault), Modify the secret
   placeholder as, 
   
   `$secret{vault:hashicorp:<alias>}`. 
   Example:
   ```toml
   [super_admin]
   username="admin"
   password="$secret{vault:hashicorp:admin_password}"
   ```

### Step 4: Start the Server

1. Provide the `VAULT_TOKEN` to the prompted message in the console or create a new file in the `<IS_HOME>` directory. 
   The file should be named according to your Operating System.
   
   ```
   For Linux   : The file name should be hashicorpRootToken-tmp.
   For Windows : The file name should be hashicorpRootToken-tmp.txt.
   ```
        
   When you add "tmp" to the file name, note that this will automatically get deleted from the file system after
   the server starts. Alternatively, if you want to retain the password file after the server starts, the file
   should be named as follows:
       
   ```
   For Linux   : The file name should be hashicorpRootToken-persist.
   For Windows : The file name should be hashicorpRootToken-persist.txt.
   ```
   
2. Start the WSO2 Identity Server and enter the keystore password at the startup when prompted.
   ```
   [Enter KeyStore and Private Key Password :] wso2carbon
   ```
