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
import dev.castive.securepass3.PasswordGenerator
import java.util.concurrent.Future

@Suppress("unused")
abstract class AbstractOAuth2Provider(internal val flow: BaseFlow) {
	abstract val sourceName: String

	// used to generate a random code for requests
	private val generator = PasswordGenerator()
	private val service = ServiceBuilder(flow.clientId)
		.apiSecret(flow.clientSecret)
		.callback(flow.callbackUrl)
		.defaultScope(flow.scope)
		.build(flow.api)

	/**
	 * Get the url for the consent screen to redirect the user
	 */
	fun getAuthoriseUrl(): String = service.getAuthorizationUrl(generator.generate(32).toString())

	/**
	 * Get an access token using the consent code
	 */
	fun getAccessToken(code: String): OAuth2AccessToken = service.getAccessToken(code)

	/**
	 * Get a new access token using our refresh token
	 */
	fun refreshToken(refreshToken: String): OAuth2AccessToken = service.refreshAccessToken(refreshToken)
	fun revokeToken(accessToken: String) = service.revokeToken(accessToken)
	/**
	 * Used for logout
	 * Async is preferred because the user isn't waiting on the result
	 */
	fun revokeTokenAsync(accessToken: String): Future<Void> = service.revokeTokenAsync(accessToken)

	/**
	 * Check if the access token is still valid
	 */
	abstract fun isTokenValid(accessToken: String): Boolean
	/**
	 * Get the information required to create a user
	 */
	abstract fun getUserInformation(accessToken: String): User2?
}