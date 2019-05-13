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

class LDAPConfig(val enabled: Boolean,
                 val server: String,
                 val port: Int = 389,
                 val contextDN: String,
                 val serviceUserDN: String,
                 val serviceUserPassword: String) {
	class Extras(val userFilter: String,
	             val uid: String,
	             val removeStale: Boolean = true,
	             val syncRate: Long = 300000,
	             val blockLocal: Boolean = false,
	             val maxConnectAttempts: Int = 5)
	class Groups(val groupFilter: String,
	             val groupQuery: String,
	             val gid: String)
}