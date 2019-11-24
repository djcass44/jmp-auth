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
import dev.castive.javalin_auth.auth.data.User2
import dev.castive.javalin_auth.auth.data.UserEntity
import dev.castive.javalin_auth.auth.external.Session
import dev.castive.javalin_auth.auth.provider.flow.BasicAuthProvider
import dev.castive.javalin_auth.util.SigningKey
import dev.castive.log2.loge
import dev.castive.log2.logi
import dev.castive.log2.logv
import io.javalin.core.security.BasicAuthCredentials

class Internal2Provider<T>(private val locator: RequestUserLocator.UserLocation<T>, private val session: Session<T>): BasicAuthProvider<T> {
	override val sourceName: String
		get() = "local"

	override fun getAccessToken(basicAuth: BasicAuthCredentials, data: Any?): OAuth2.TokenResponse? {
		val user = locator.findByBasic(basicAuth.username, basicAuth.password) ?: kotlin.run {
			"Unable to create accessToken for user: ${basicAuth.username} because they couldn't be found".logi(javaClass)
			return null
		}
		return session.createSession(user)
	}

	override fun refreshToken(token: String, data: Any?): OAuth2.TokenResponse? {
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
		session.disableSessions(token)
	}

	override fun isTokenValid(token: String, data: Any?): Boolean {
		SigningKey.jwtHelper.verify(token) ?: kotlin.run {
			"Unable to get userId from jwt: $token".logv(javaClass)
			return false
		}
		return true
	}

	override fun getUserByName(username: String, data: Any?): User2? {
		val user = locator.findUserByUsername(username, sourceName) ?: run {
			"Unable to find user with username: $username".logv(javaClass)
			return null
		}
		return User2(user.username, "", "", sourceName, "user")
	}

	override fun getUser(token: String, data: Any?): UserEntity<T>? {
		val userId = SigningKey.jwtHelper.verify(token) ?: kotlin.run {
			"Unable to get userId from jwt: $token".logv(javaClass)
			return null
		}
		return locator.findUserById(userId)
	}
}