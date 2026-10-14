/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
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

import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.api.Auth;
import com.bettercloud.vault.response.AuthResponse;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;

/**
 * Unit tests for the custom AppRole auth path support in {@link HashiCorpSecretRepository}.
 */
public class HashiCorpSecretRepositoryTest {

    private static final String ROLE_ID = "test-role-id";
    private static final String SECRET_ID = "test-secret-id";

    @DataProvider(name = "validAuthPaths")
    public Object[][] validAuthPaths() {

        return new Object[][]{
                {"/auth/approle", "approle"},
                {"/auth/approle/wso2", "approle/wso2"},
                {"auth/approle/wso2", "approle/wso2"},
                {"/auth/approle/wso2/", "approle/wso2"},
                {" /auth/approle/wso2/ ", "approle/wso2"},
                {"approle/wso2", "approle/wso2"},
                {"/approle/wso2", "approle/wso2"},
                {"/auth/team-a/approle", "team-a/approle"},
                // Only an exact "auth/" prefix is removed.
                {"/authx/approle", "authx/approle"},
        };
    }

    @Test(dataProvider = "validAuthPaths")
    public void testGetConfiguredAppRoleAuthPath(String configuredPath, String expectedMountPath) {

        assertEquals(HashiCorpSecretRepository.getConfiguredAppRoleAuthPath(configuredPath), expectedMountPath);
    }

    @DataProvider(name = "unsetOrInvalidAuthPaths")
    public Object[][] unsetOrInvalidAuthPaths() {

        return new Object[][]{
                {null},
                {""},
                {"   "},
                {"/"},
                {"//"},
                {"/auth"},
                {"/auth/"},
                {"auth/"},
        };
    }

    @Test(dataProvider = "unsetOrInvalidAuthPaths")
    public void testGetConfiguredAppRoleAuthPathReturnsNullWhenUnsetOrInvalid(String configuredPath) {

        assertNull(HashiCorpSecretRepository.getConfiguredAppRoleAuthPath(configuredPath));
    }

    @Test
    public void testLoginByAppRoleUsesDriverDefaultWhenAuthPathIsNotConfigured() throws VaultException {

        Auth auth = mock(Auth.class);
        AuthResponse authResponse = mock(AuthResponse.class);
        when(auth.loginByAppRole(ROLE_ID, SECRET_ID)).thenReturn(authResponse);

        AuthResponse response = HashiCorpSecretRepository.loginByAppRole(auth, null, ROLE_ID, SECRET_ID);

        assertSame(response, authResponse);
        verify(auth).loginByAppRole(ROLE_ID, SECRET_ID);
        verify(auth, never()).loginByAppRole(anyString(), anyString(), anyString());
    }

    @Test
    public void testLoginByAppRoleUsesConfiguredAuthPath() throws VaultException {

        Auth auth = mock(Auth.class);
        AuthResponse authResponse = mock(AuthResponse.class);
        when(auth.loginByAppRole("approle/wso2", ROLE_ID, SECRET_ID)).thenReturn(authResponse);

        AuthResponse response = HashiCorpSecretRepository.loginByAppRole(auth, "approle/wso2", ROLE_ID, SECRET_ID);

        assertSame(response, authResponse);
        verify(auth).loginByAppRole("approle/wso2", ROLE_ID, SECRET_ID);
        verify(auth, never()).loginByAppRole(anyString(), anyString());
    }

    @Test
    public void testConfiguredAuthPathIsResolvedAndPassedToDriver() throws VaultException {

        Auth auth = mock(Auth.class);
        String mountPath = HashiCorpSecretRepository.getConfiguredAppRoleAuthPath("/auth/approle/wso2");

        HashiCorpSecretRepository.loginByAppRole(auth, mountPath, ROLE_ID, SECRET_ID);

        verify(auth).loginByAppRole("approle/wso2", ROLE_ID, SECRET_ID);
    }

    @Test
    public void testUnsetAuthPathFallsBackToDriverDefault() throws VaultException {

        Auth auth = mock(Auth.class);
        String mountPath = HashiCorpSecretRepository.getConfiguredAppRoleAuthPath(null);

        HashiCorpSecretRepository.loginByAppRole(auth, mountPath, ROLE_ID, SECRET_ID);

        verify(auth).loginByAppRole(ROLE_ID, SECRET_ID);
        verify(auth, never()).loginByAppRole(anyString(), anyString(), anyString());
    }

    @Test(expectedExceptions = VaultException.class)
    public void testLoginByAppRolePropagatesVaultException() throws VaultException {

        Auth auth = mock(Auth.class);
        when(auth.loginByAppRole("approle/wso2", ROLE_ID, SECRET_ID))
                .thenThrow(new VaultException("Vault responded with HTTP status code: 400"));

        HashiCorpSecretRepository.loginByAppRole(auth, "approle/wso2", ROLE_ID, SECRET_ID);
    }
}
