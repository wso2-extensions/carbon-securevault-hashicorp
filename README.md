# Intergrate HashiCorp Vault with WSO2 Identity Server

## Setting up using root token auth method

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
the `target/org.wso2.carbon.securevault.hashicorp-1.0.jar` file to `<IS_HOME>/repository/components/dropin/`
directory.

2. Add **HashiCorp Vault Java Driver** (Eg: `vault-java-driver-5.1.0.jar`) to the
`<IS_HOME>/repository/components/lib/` directory.

3. Open `/repository/conf/security/secret-conf.properties` file and set following configurations.
    ```
    keystore.identity.location=repository/resources/security/wso2carbon.jks
    keystore.identity.type=JKS
    keystore.identity.store.password=identity.store.password
    keystore.identity.store.secretProvider=org.wso2.carbon.securevault.DefaultSecretCallbackHandler
    keystore.identity.key.password=identity.key.password
    keystore.identity.key.secretProvider=org.wso2.carbon.securevault.DefaultSecretCallbackHandler
    carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler
    
    secVault.enabled=true
    secretRepositories=vault
    secretRepositories.vault.provider=org.wso2.carbon.securevault.hashicorp.repository.HashiCorpSecretRepositoryProvider
    secretRepositories.vault.properties.address=https://127.0.0.1:8200
    secretRepositories.vault.properties.namespace=ns1
    secretRepositories.vault.properties.enginePath=wso2is
    secretRepositories.vault.properties.engineVersion=2
    secretRepositories.vault.properties.authType=ROOT_TOKEN
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
   loggers = AUDIT_LOG, trace-messages, ... ,org-wso2-carbon-securevault-hashicorp
   ```

### Step 3: Update passwords with their aliases
1. Open the `deployment.toml` file in the `<IS_HOME>/repository/conf/` directory and add
   the `[secrets]` configuration section **at the bottom of the file** as shown below.
   Give an alias for the passwords and put the value as blank (`""`).

    ```toml
    [secrets]
    admin_password = ""
    keystore_password = ""
    database_password = ""
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

### Step 4: Start the Server

1. Provide the `VAULT_TOKEN` to the prompted message in the console or by creating a new file in the `<IS_HOME>` directory. 
The file should be named according to your Operating System.

    ```
    For Linux   : The file name should be hashicorpRootToken-tmp.
    For Windows : The file name should be hashicorpRootToken-tmp.txt.
    ```
    When you add "tmp" to the file name, note that this will automatically get deleted from the file system after server
    starts. Alternatively, if you want to retain the password file after the server starts, the file should be named as follows:
    ```
    For Linux   : The file name should be hashicorpRootToken-persist.
    For Windows : The file name should be hashicorpRootToken-persist.txt.
    ```
   
2. Start the WSO2 Identity Server and enter the keystore password at the startup when prompted.
   ```
   [Enter KeyStore and Private Key Password :] wso2carbon
   ```
## Setting up using app role auth method

### Step 1: Setup HashiCorp Vault

1. Start HashiCorp vault server and set environment variables

   ```
      export VAULT_ADDR='http://127.0.0.1:8200'
      export VAULT_TOKEN='<root token>'
      ``` 
   Include policy in `kv-read-write.hcl` file as below

   ```
   path "wso2is/data/*" {
     capabilities = ["create", "read", "update", "delete", "list"]
   }
   ```

   Upload kv policy as bellow

   ```
   vault policy write kv-read-write kv-read-write.hcl
   ```

   Following command can be used to create app role using created policy

   ```
      # Create a new approle
      vault auth enable approle
   ```
   ```
      vault write auth/approle/role/my-role \
         token_policies="kv-read-write" \
         token_type="service" \
         token_ttl="24h" \
         token_max_ttl="72h"
      ```  

   Get the role-id as bellow
   ```
   vault read auth/approle/role/my-role/role-id
   ```

   Get the secret-id as bellow

   ```
   vault write -f auth/approle/role/my-role/secret-id
   ```

   Enter a Path name when creating the kv engine (Eg: `wso2is`).

   Following commands can be used to add secrets with the HashiCorp vault.

   ```
   # Create a new kv engine
   vault secrets enable -path=wso2is -version=2 kv
   
   # Add new secret
   vault kv put wso2is/admin_password value=wso2carbon
   
   # Get a secret (To check)
   vault kv get -field=value wso2is/admin_password
   ```

### Step 2: Configure HashiCorp Vault extension

1. Build the HashiCorp Vault Integration OSGI bundle using `mvn clean install` and copy
   the `target/org.wso2.carbon.securevault.hashicorp-1.0.jar` file to `<IS_HOME>/repository/components/dropin/`
   directory.

2. Add **HashiCorp Vault Java Driver** (Eg: `vault-java-driver-5.1.0.jar`) to the
   `<IS_HOME>/repository/components/lib/` directory.

3. Open `/repository/conf/security/secret-conf.properties` file and set following configurations.
    ```
    keystore.identity.location=repository/resources/security/wso2carbon.jks
    keystore.identity.type=JKS
    keystore.identity.store.password=identity.store.password
    keystore.identity.store.secretProvider=org.wso2.carbon.securevault.DefaultSecretCallbackHandler
    keystore.identity.key.password=identity.key.password
    keystore.identity.key.secretProvider=org.wso2.carbon.securevault.DefaultSecretCallbackHandler
    carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler
    
   secVault.enabled=true
   secretRepositories=vault
   secretRepositories.vault.provider=org.wso2.carbon.securevault.hashicorp.repository.HashiCorpSecretRepositoryProvider
   secretRepositories.vault.properties.address=https://127.0.0.1:8200
   secretRepositories.vault.properties.namespace=ns1
   secretRepositories.vault.properties.enginePath=wso2is
   secretRepositories.vault.properties.engineVersion=2
   secretRepositories.vault.properties.authType=APP_ROLE
   secretRepositories.vault.properties.roleId=<role id>
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
   loggers = AUDIT_LOG, trace-messages, ... ,org-wso2-carbon-securevault-hashicorp
   ```

### Step 3: Update passwords with their aliases
1. Open the `deployment.toml` file in the `<IS_HOME>/repository/conf/` directory and add
   the `[secrets]` configuration section **at the bottom of the file** as shown below.
   Give an alias for the passwords and put the value as blank (`""`).

    ```toml
    [secrets]
    admin_password = ""
    ```

2. Add the encrypted password alias to the relevant sections in the `deployment.toml`
   file by using a place holder: `$secret{alias}`. For example:

    ```toml
    [super_admin]
    username="admin"
    password="$secret{admin_password}"
    ```

### Step 4: Start the Server

1. Provide the `Secret ID` to the prompted message in the console or by creating a new file in the `<IS_HOME>`
   directory.
   The file should be named according to your Operating System.

    ```
    For Linux   : The file name should be hashicorpSecretId-tmp.
    For Windows : The file name should be hashicorpSecretId-tmp.txt.
    ```
   When you add "tmp" to the file name, note that this will automatically get deleted from the file system after server
   starts. Alternatively, if you want to retain the password file after the server starts, the file should be named as follows:
    ```
    For Linux   : The file name should be hashicorpSecretId-persist.
    For Windows : The file name should be hashicorpSecretId-persist.txt.
    ```

2. Start the WSO2 Identity Server and enter the keystore password at the startup when prompted.
   ```
   [Enter KeyStore and Private Key Password :] wso2carbon
   ```
