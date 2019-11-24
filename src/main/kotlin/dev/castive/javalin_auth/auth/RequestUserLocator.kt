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

package dev.castive.javalin_auth.auth

import dev.castive.javalin_auth.api.OAuth2
import dev.castive.javalin_auth.auth.data.User2
import dev.castive.javalin_auth.auth.data.UserEntity
import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.Factor
import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.ValidateRequest
import dev.castive.javalin_auth.auth.provider.Crowd2Provider
import dev.castive.javalin_auth.config.Crowd2Config
import dev.castive.javalin_auth.util.SigningKey
import dev.castive.log2.logd
import dev.castive.log2.loge
import dev.castive.log2.logi
import dev.castive.log2.logv
import dev.dcas.util.extend.decodeBase64Url
import io.javalin.http.Context
import io.javalin.http.UnauthorizedResponse

@Suppress("unused", "MemberVisibilityCanBePrivate")
class RequestUserLocator<T: Any>(
	private val locator: UserLocation<T>,
	private val crowdConfig: Crowd2Config
) {
	val headerAuth = "Authorization"
	val headerSource = "X-Auth-Source"

	interface UserLocation<T> {
		fun findUserByUsername(username: String, source: String): UserEntity<T>?
		fun createUser(user: User2): UserEntity<T>
		fun findUserById(id: String?): UserEntity<T>?
		fun findActiveSession(requestToken: String): Pair<UserEntity<T>, String>?
		fun findByBasic(username: String, password: String): UserEntity<T>?
	}

	private val crowd = getCrowd()

	/**
	 * Get the user from the Authorization header OR a Cookie (e.g. Crowd SSO)
	 * @throws UnauthorizedResponse if the user couldn't be found
	 */
	fun assertUser(ctx: Context): UserEntity<T>? = getUser(ctx) ?: throw UnauthorizedResponse()

	/**
	 * Get the user from the Authorization header
	 * @throws UnauthorizedResponse if the user couldn't be found
	 */
	fun assertUser(bearer: String, source: String?): UserEntity<T> = getUser(bearer, source) ?: throw UnauthorizedResponse()

	/**
	 * Get the user from the Authorization header OR a Cookie (e.g. Crowd SSO)
	 */
	fun getUser(ctx: Context): UserEntity<T>? {
		val (auth, source) = getHeaders(ctx.headerMap())
		// if special checking is required (e.g. the crowd cookie), do it here
		val user = checkCrowd(ctx)
		// otherwise, get the user from the Authorization header
		return user ?: getUser(auth ?: "", source)
	}

	/**
	 * Get the user from the authorization header
	 */
	fun getUser(bearer: String, source: String?): UserEntity<T>? {
		// get the Authorization header
		val (type, code) = getAuthHeader(bearer) ?: run {
			"Got null token, unable to determine user".logv(javaClass)
			return null
		}
		// check the header is the right scope
		if(type.isBlank()) {
			"Got invalid Authorization type: $type".logi(javaClass)
		}
		return when(type) {
			"Bearer" -> checkBearer(code, source)
			"Basic" -> checkBasic(code)
			else -> {
				"Unknown Authorization type: $type".loge(javaClass)
				null
			}
		}
	}

	/**
	 * Check whether the user has a valid SSO session with Crowd
	 */
	private fun checkCrowd(ctx: Context): UserEntity<T>? {
		// if crowd isn't enabled, don't bother checking
		if(crowd == null) {
			"Skipping Crowd check because Crowd integration is disabled".logv(javaClass)
			return null
		}
		// get the name of the cookie
		val cookieName = crowd.cookieConfig?.name ?: run {
			"Crowd cookie could not be found".logv(javaClass)
			return null
		}
		"Checking for crowd cookie: $cookieName".logd(javaClass)
		// get the cookie value
		val cookie = ctx.cookie(cookieName) ?: run {
			"Could not find cookie with name: $cookieName".logv(javaClass)
			"Attempting Crowd fallback using Authorization header".logi(javaClass)
			return@run getAuthHeader(ctx.header(headerAuth))?.second ?: return null
		}
		"Found Crowd cookie with value: $cookie".logd(javaClass)
		// check the cache first
		val cachedUser = Providers.cache[cookie]?.let {
			locator.findUserById(it)
		}
		if(cachedUser != null) {
			"Found cache Crowd user: ${cachedUser.username}".logv(javaClass)
			return cachedUser
		}
		val user = crowd.getUser(cookie, ValidateRequest(listOf(Factor("remote_address", ctx.ip()))))
		user?.let {
			// if we found a user, add them to the cache
			Providers.cache[cookie] = user.id.toString()
		}
		return user
	}

	private fun checkBasic(token: String): UserEntity<T>? {
		val (username, password) = token.decodeBase64Url().split(":")
		"Got basic-auth request with username '$username'".logi(javaClass)
		return locator.findByBasic(username, password)
	}

	private fun checkBearer(token: String, source: String?): UserEntity<T>? {
		val cachedUser = Providers.cache[token]?.let {
			locator.findUserById(it)
		}
		if(cachedUser != null) {
			"Found cached user: ${cachedUser.username}".logv(javaClass)
			return cachedUser
		}
		// JWT must start with ey (base64 ot '{')
		if(token.startsWith("ey")) {
			if(!isJwtValid(token))
				return null
		}
		else if(!isOAuth2Valid(token, source))
			return null
		// get the session
		val session = locator.findActiveSession(token)
		"Located session: ${session?.second} for user: ${session?.first?.username}".logi(javaClass)
		if(session?.first == null)
			"Failed to locate active user session".logi(javaClass)
		else {
			"Added user: ${session.first.username} to cache".logv(javaClass)
			Providers.cache[token] = session.first.id.toString()
		}
		return session?.first
	}

	private fun isOAuth2Valid(token: String, source: String?): Boolean {
		// get the user claim from the header
		val provider = OAuth2.providers[source] ?: kotlin.run {
			"Could not find provider: '$source' for token: $token".loge(javaClass)
			return false
		}
		return if(!provider.isTokenValid(token)) {
			"OAuth2 token is invalid for provider $source".loge(javaClass)
			false
		}
		else
			true
	}

	private fun isJwtValid(token: String): Boolean {
		// get the user claim from the header
		return null != locator.findUserById(SigningKey.jwtHelper.verify(token)) ?: run {
			"Token verification failed".logi(javaClass)
			return false
		}
	}

	/**
	 * Extract the important information from an 'Authorization' header
	 * Expects a string containing <type> <token> e.g. Bearer ey-blah-blah-a-jwt
	 */
	private fun getAuthHeader(header: String?): Pair<String, String>? {
		if(header == null)
			return null
		val auth = runCatching {
			header.split(" ")
		}.getOrNull() ?: return null
		if(auth.size < 2) return null
		return auth[0] to auth[1]
	}

	private fun getHeaders(headers: Map<String, String>): List<String?> {
		val auth = headers[headerAuth]
		val source = headers[headerSource]
		return listOf(auth, source)
	}

	private fun getCrowd(): Crowd2Provider<T>? = if(crowdConfig.enabled)
		Crowd2Provider(locator, crowdConfig)
	else null
}