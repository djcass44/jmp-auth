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

import com.github.kittinunf.fuel.core.FuelManager
import com.github.kittinunf.fuel.gson.responseObject
import com.github.kittinunf.result.Result
import dev.castive.javalin_auth.api.OAuth2
import dev.castive.javalin_auth.auth.RequestUserLocator
import dev.castive.javalin_auth.auth.data.User2
import dev.castive.javalin_auth.auth.data.UserEntity
import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.*
import dev.castive.javalin_auth.auth.provider.flow.BasicAuthProvider
import dev.castive.javalin_auth.config.Crowd2Config
import dev.castive.log2.*
import dev.dcas.util.extend.json
import dev.dcas.util.extend.parse
import dev.dcas.util.extend.toBasic
import io.javalin.core.security.BasicAuthCredentials

class Crowd2Provider<T>(
	private val locator: RequestUserLocator.UserLocation<T>,
	private val config: Crowd2Config
): BasicAuthProvider<T> {
	/**
	 * Create a custom fuel instance with default headers
	 */
	private val fuel = FuelManager().apply {
		basePath = config.url
		baseHeaders = mapOf(
			"Authorization" to (config.username to config.password).toBasic(),
			"Content-Type" to "application/json",
			"Accept" to "application/json"
		)
	}

	val cookieConfig = getSSOConfig()

	override val sourceName: String
		get() = "crowd"

	override fun getAccessToken(basicAuth: BasicAuthCredentials, data: Any?): OAuth2.TokenResponse? {
		if(!config.enabled) return null
		val factors = if(data == null || data !is String) {
			"Unable to send Crowd validation factors, this may cause login issues".logw(javaClass)
			null
		}
		else {
			"Using validation factors: $data".logd(javaClass)
			data.parse(ValidationFactors::class.java)
		}
		val (_, _, result) = fuel.post("/rest/usermanagement/1/session")
			.body(AuthenticateRequest(basicAuth.username, basicAuth.password, factors).json())
			.responseObject<AuthenticateResponse>()
		return when(result) {
			is Result.Failure -> {
				Log.e(javaClass, "Failed to authenticate ${basicAuth.username}, ${result.getException().exception}")
				null
			}
			is Result.Success -> {
				val res = result.get()
				"${sourceName.capitalize()} created a new session for ${res.user.name}".logi(javaClass)
				"Created session with token: ${res.token}".logd(javaClass)
				OAuth2.TokenResponse(res.token, res.token, sourceName)
			}
		}
	}

	/**
	 * Crowd doesn't support refreshing the SSO token, so do nothing
	 */
	override fun refreshToken(token: String, data: Any?): OAuth2.TokenResponse? = null

	override fun isTokenValid(token: String, data: Any?): Boolean = getUser(token, data) != null

	override fun getUserByName(username: String, data: Any?): User2? {
		if(!config.enabled) return null
		// this endpoint gives us some (not all) information about a user
		val (_, _, result) = fuel.get("/rest/usermanagement/1/user?username=$username").responseString()
		return when(result) {
			is Result.Success -> {
				val res = result.get()
				// extract the fields we want (username, display name)
				val user = res.parse(User::class.java)
				"Located Crowd user: ${user.displayName}".logi(javaClass)
				User2(user.name, user.displayName ?: user.name, "", sourceName, "user")
			}
			else -> null
		}
	}

	override fun getUser(token: String, data: Any?): UserEntity<T>? {
		if(!config.enabled) return null
		if(data == null || data !is ValidateRequest) {
			"getUser data is null or not a ${ValidateRequest::class.java.name}".loge(javaClass)
			return null
		}
		val (_, _, result) = fuel.post("/rest/usermanagement/1/session/$token").body(data.json()).responseObject<AuthenticateResponse>()
		return when(result) {
			is Result.Failure -> {
				"Failed to validate Crowd SSO token: $token, ${result.getException().exception}".loge(javaClass)
				null
			}
			is Result.Success -> {
				val res = result.get()
				"Validated SSO token for ${res.user.name}, expires at ${res.expiryDate}".logok(javaClass)
				return if(System.currentTimeMillis() < res.expiryDate)
					locator.findUserByUsername(res.user.name, sourceName) ?: locator.createUser(getUserByName(res.user.name) ?: return null)
				else
					null
			}
		}
	}

	override fun revokeToken(token: String, data: Any?) {
		if(!config.enabled) return
		fuel.delete("/rest/usermanagement/1/session/${token}")
			.responseString { it ->
				"Invalidated token: $token, response: ${it.get()}".logi(javaClass)
			}.join()
	}

	/**
	 * Loads the cookie configuration from Crowd
	 */
	private fun getSSOConfig(): CrowdCookieConfig? {
		if(!config.enabled) return null
		val (_, _, result) = fuel.get("/rest/usermanagement/1/config/cookie")
			.responseObject<CrowdCookieConfig>()
		return when(result) {
			is Result.Failure -> {
				"Failed to get Crowd cookie config:, ${result.getException().exception}".loge(Crowd2Provider::class.java)
				null
			}
			is Result.Success -> {
				val res = result.get()
				"Using Crowd cookie ${res.name} for domain ${res.domain}".logi(Crowd2Provider::class.java)
				res
			}
		}
	}
}