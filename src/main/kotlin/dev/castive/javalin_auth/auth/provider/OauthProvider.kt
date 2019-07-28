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

import com.github.kittinunf.fuel.core.FuelError
import com.github.kittinunf.fuel.core.FuelManager
import com.github.kittinunf.fuel.core.Request
import com.github.kittinunf.fuel.core.Response
import com.github.kittinunf.fuel.gson.responseObject
import com.github.kittinunf.result.Result
import com.github.scribejava.apis.GitHubApi
import com.github.scribejava.core.builder.ServiceBuilder
import com.github.scribejava.core.model.OAuth2AccessToken
import dev.castive.javalin_auth.auth.data.User2
import dev.castive.javalin_auth.auth.data.model.github.GitHubUser
import dev.castive.javalin_auth.auth.provider.flow.BaseFlow
import dev.castive.log2.Log
import dev.castive.securepass3.PasswordGenerator

class OauthProvider {
	val SOURCE_NAME = "oauth2"

	// using GitHub for now, will generify once working
	private val flow = BaseFlow(
		"https://github.com/login/oauth/authorize",
		apiUrl = "https://api.github.com",
		callbackUrl = "http://localhost:3000/callback",
		scope = "read:user",
		clientId = "",
		clientSecret = "",
		api = GitHubApi.instance()
	)

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
	fun revokeTokenAsync(accessToken: String) = service.revokeTokenAsync(accessToken)

	/**
	 * Check if the access token is still valid
	 */
	fun isTokenValid(accessToken: String): Boolean {
//		var valid = false
//		val r = FuelManager.instance.get("${flow.apiUrl}/applications/${flow.clientId}/token/$accessToken")
//			.appendHeader("Authorization", Util.basicAuth(flow.clientId, flow.clientSecret))
//			.responseObject { _: Request, response: Response, result: Result<String, FuelError> ->
//				val code = response.statusCode
//				Log.d(javaClass, "Got response code: $code")
//				Log.d(javaClass, "Got response body: ${result.component1()}")
//				// 200 means that token is OK, 400 is invalid
//				valid = code == 200
//			}
//		r.join()
//		return valid
		return true
	}

	/**
	 * Get the information required to create a user
	 */
	fun getUserInformation(accessToken: String): User2? {
		var user: User2? = null
		val r = FuelManager.instance.get("${flow.apiUrl}/user")
			.appendHeader("Authorization", "token $accessToken")
			.responseObject { _: Request, response: Response, result: Result<GitHubUser, FuelError> ->
				if(response.statusCode != 200) {
					Log.e(javaClass, "Failed to load user information: ${result.component2()?.exception}")
					return@responseObject
				}
				// Assume nothing else has gone wrong
				user = User2(result.get())
			}
		// wait for a response
		r.join()
		return user
	}
}