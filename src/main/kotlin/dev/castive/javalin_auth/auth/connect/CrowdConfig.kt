/*
 *    Copyright 2019 Django Cass
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 */

package dev.castive.javalin_auth.auth.connect

import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.BasicAuthentication

data class CrowdConfig(override val enabled: Boolean, override val serviceAccount: BasicAuthentication, val crowdUrl: String,
                       override val syncRate: Long = 300000,
                       override val maxConnectAttempts: Int = 5,
                       override val blockLocal: Boolean = false,
                       override val removeStale: Boolean = true
) : BaseConfig {
    constructor(min: MinimalConfig, crowdUrl: String): this(min.enabled, min.serviceAccount, crowdUrl, min.syncRate, min.maxConnectAttempts, min.blockLocal, min.removeStale)
}