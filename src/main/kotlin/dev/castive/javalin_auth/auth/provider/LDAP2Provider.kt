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

package dev.castive.javalin_auth.auth.provider

import dev.castive.javalin_auth.api.OAuth2
import dev.castive.javalin_auth.auth.RequestUserLocator
import dev.castive.javalin_auth.auth.connect.LDAPConnection
import dev.castive.javalin_auth.auth.data.User2
import dev.castive.javalin_auth.auth.data.UserEntity
import dev.castive.javalin_auth.auth.external.Session
import dev.castive.javalin_auth.auth.provider.flow.BasicAuthProvider
import dev.castive.javalin_auth.config.LDAP2Config
import dev.castive.javalin_auth.util.SigningKey
import dev.castive.log2.Log
import dev.castive.log2.loge
import dev.castive.log2.logi
import dev.castive.log2.logv
import io.javalin.core.security.BasicAuthCredentials
import javax.naming.directory.SearchResult

class LDAP2Provider<T>(
	private val locator: RequestUserLocator.UserLocation<T>,
	private val session: Session<T>,
	private val config: LDAP2Config
): BasicAuthProvider<T> {
	override val sourceName: String
		get() = "ldap"

	private val connection: LDAPConnection = LDAPConnection(config)

	override fun getAccessToken(basicAuth: BasicAuthCredentials, data: Any?): OAuth2.TokenResponse? {
		if(!config.enabled) return null
		// check that the credentials are valid LDAP credentials
		return if(connection.checkUserAuth(basicAuth.username, basicAuth.password)) {
			val user = locator.findUserByUsername(basicAuth.username, sourceName) ?: run {
				// pull user information from the directory and store it in the database
				connection.search(basicAuth.username)?.let { res ->
					getUserFromSearch(res)?.let {
						return@run locator.createUser(it)
					}
				}
			}
			if(user == null) {
				"Unable to create session for user ${basicAuth.username} as they couldn't be found".loge(javaClass)
				null
			}
			else
				session.createSession(user)
		}
		else
			null
	}

	override fun refreshToken(token: String, data: Any?): OAuth2.TokenResponse? {
		if(!config.enabled) return null
		if(SigningKey.jwtHelper.verify(token) == null) {
			"Unable to refresh invalid token: $token".loge(javaClass)
			return null
		}
		val user = session.getForRefresh(token) ?: kotlin.run {
			"Unable to find matching, active session for token: $token".logv(javaClass)
			return null
		}
		"Refreshing session for ${user.username}".logi(javaClass)
		return session.createSession(user)
	}

	override fun revokeToken(token: String, data: Any?) {
		if(!config.enabled) return
		session.disableSessions(token)
	}

	override fun isTokenValid(token: String, data: Any?): Boolean {
		if(!config.enabled) return false
		SigningKey.jwtHelper.verify(token) ?: kotlin.run {
			"Unable to get userId from jwt: $token".logv(javaClass)
			return false
		}
		return true
	}

	override fun getUserByName(username: String, data: Any?): User2? {
		if(!config.enabled) return null
		val user = locator.findUserByUsername(username, sourceName) ?: run {
			"Unable to find user with username: $username".logv(javaClass)
			return null
		}
		return User2(user.username, "", "", sourceName, "user")
	}

	override fun getUser(token: String, data: Any?): UserEntity<T>? {
		if(!config.enabled) return null
		val userId = SigningKey.jwtHelper.verify(token) ?: kotlin.run {
			"Unable to get userId from jwt: $token".logv(javaClass)
			return null
		}
		return locator.findUserById(userId)
	}

	private fun getUserFromSearch(search: SearchResult): User2? {
		val username = kotlin.runCatching { search.attributes.get(config.uidField).get(0).toString() }.getOrNull()
		if(username == null) {
			Log.e(javaClass, "Failed to read name of user, dumping attributes for manual fix: ${runCatching { return@runCatching search.attributes }}")
			return null
		}
		Log.d(javaClass, "Parsing LDAP username: $username")
		// try to get the displayName
		val displayName = kotlin.runCatching {
			search.attributes.get("cn").get().toString()
		}.getOrNull()
		val role = kotlin.runCatching { search.attributes.get("objectClass").get(0).toString() }.getOrNull() ?: run {
			Log.e(javaClass, "Failed to read objectClass of user, dumping attributes for manual fix: ${runCatching { return@runCatching search.attributes }}")
			"user"
		}
		return User2(username, displayName ?: username, "", sourceName, role)
	}
}