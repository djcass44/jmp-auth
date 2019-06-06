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
 */

package dev.castive.javalin_auth.auth.connect

import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.BasicAuthentication

class LDAPConfig(val server: String,
                 val port: Int = 389,
                 val contextDN: String) {
	class Extras(val userFilter: String,
	             val uid: String,
	             val removeStale: Boolean = true,
	             val blockLocal: Boolean = false,
				 val reconnectOnAuth: Boolean = false)
	class Groups(val groupFilter: String,
	             val groupQuery: String,
	             val gid: String)
}
class LDAPConfig2(override val enabled: Boolean,
                  override val serviceAccount: BasicAuthentication,
                  override val syncRate: Long = 300000,
                  override val maxConnectAttempts: Int = 5,
                  val baseConfig: LDAPConfig,
                  val extraConfig: LDAPConfig.Extras,
                  val groupConfig: LDAPConfig.Groups
) : BaseConfig