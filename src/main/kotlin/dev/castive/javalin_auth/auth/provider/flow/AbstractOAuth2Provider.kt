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

package dev.castive.javalin_auth.auth.provider.flow

import com.github.scribejava.core.builder.ServiceBuilder
import com.github.scribejava.core.model.OAuth2AccessToken
import dev.castive.javalin_auth.auth.data.User2
import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.BasicAuthentication
import dev.dcas.util.extend.base64Url
import dev.dcas.util.extend.decodeBase64Url
import dev.dcas.util.extend.randomString
import java.util.concurrent.Future

@Suppress("unused")
abstract class AbstractOAuth2Provider(internal val provider: BaseFlow) {
	companion object {
		fun parseState(state: String): Triple<String, String, String> {
			val (name, meta, code) = state.decodeBase64Url().split(":", limit = 3)
			return Triple(name, meta, code)
		}
	}

	abstract val sourceName: String

	internal val service = ServiceBuilder(provider.clientId)
		.apiSecret(provider.clientSecret)
		.callback(provider.callbackUrl)
		.defaultScope(provider.scope)
		.build(provider.api)

	/**
	 * Get the url for the consent screen to redirect the user
	 */
	fun getAuthoriseUrl(meta: String = ""): String = service.getAuthorizationUrl(getState(meta))

	/**
	 * Get an access token using the consent code
	 */
	fun getAccessToken(code: String): OAuth2AccessToken = service.getAccessToken(code)

	/**
	 * Gets a token using basic authentication
	 */
	open fun getBasicAccessToken(basicAuth: BasicAuthentication, data: Any? = null): OAuth2AccessToken = throw NotImplementedError("This method must be overridden")

	/**
	 * Get a new access token using our refresh token
	 */
	fun refreshToken(refreshToken: String): OAuth2AccessToken = service.refreshAccessToken(refreshToken)
	open fun revokeToken(accessToken: String) = service.revokeToken(accessToken)
	/**
	 * Used for logout
	 * Async is preferred because the user isn't waiting on the result
	 */
	open fun revokeTokenAsync(accessToken: String): Future<*> = service.revokeTokenAsync(accessToken)

	/**
	 * Check if the access token is still valid
	 */
	abstract fun isTokenValid(accessToken: String, data: Any? = null): Boolean
	/**
	 * Get the information required to create a user
	 */
	abstract fun getUserInformation(accessToken: String): User2?

	private fun getState(meta: String = ""): String = "$sourceName:$meta:${32.randomString()}".base64Url()
}