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
package org.wso2.carbon.securevault.hashicorp.common;

import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;

/**
 * HashiCorp vault constants.
 */
public class HashiCorpVaultConstants {

    private HashiCorpVaultConstants() {}

    public static final String CONFIG_FILE_PATH = CarbonUtils.getCarbonConfigDirPath() + File.separator +
            "security" + File.separator + "secret-conf.properties";

    public static final String ADDRESS_PARAMETER = "address";
    public static final String NAMESPACE_PARAMETER = "namespace";
    public static final String ENGINE_PATH_PARAMETER = "enginePath";
    public static final String ENGINE_VERSION_PARAMETER = "engineVersion";

    public static final int DEFAULT_ENGINE_VERSION = 2;

    public static final String VALUE_PARAMETER = "value";

    public static final String CARBON_HOME = "carbon.home";
}
