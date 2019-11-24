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

import com.github.scribejava.apis.GoogleApi20
import com.github.scribejava.core.model.OAuthRequest
import com.github.scribejava.core.model.Verb
import dev.castive.javalin_auth.auth.data.User2
import dev.castive.javalin_auth.auth.data.model.google.GoogleUser
import dev.castive.javalin_auth.auth.provider.flow.AbstractOAuth2Provider
import dev.castive.javalin_auth.auth.provider.flow.BaseFlow
import dev.castive.javalin_auth.config.OAuth2Config
import dev.castive.log2.Log
import dev.castive.log2.logi
import dev.dcas.util.extend.parse

@Suppress("unused")
class GoogleProvider(config: OAuth2Config): AbstractOAuth2Provider(
	BaseFlow(
		authorizeUrl = "www.googleapis.com/oauth2/v4/token",
		apiUrl = "https://www.googleapis.com/oauth2",
		callbackUrl = config.callbackUrl,
		scope = "profile",
		clientId = config.clientId,
		clientSecret = config.clientSecret,
		api = GoogleApi20.instance()
	)
) {
	override val sourceName: String
		get() = "google"

	override fun isTokenValid(accessToken: String, data: Any?): Boolean {
		return true
	}

	override fun getUserInformation(accessToken: String): User2? {
		// Create an sign the request
		val request = OAuthRequest(Verb.GET, "${provider.apiUrl}/v3/userinfo")
		service.signRequest(accessToken, request)
		val response = service.execute(request)
		// If the request failed, return null
		if(!response.isSuccessful) {
			Log.e(javaClass, "Failed to load user information: ${response.body}, ${response.message}")
			return null
		}
		Log.d(javaClass, "Got response from google: ${response.body}")
		val res = response.body.parse(GoogleUser::class.java)
		return User2(res)
	}

	/**
	 * Check that an ID token is valid
	 * https://developers.google.com/identity/protocols/OpenIDConnect#validatinganidtoken
	 */
	private fun validateTokenResponse(user: GoogleUser): Boolean {
		"Validating Google response: [iss: ${user.iss}, aud: ${user.aud}, exp: ${user.exp}".logi(javaClass)
		return when {
			user.iss != "https://accounts.google.com" && user.iss != "accounts.google.com" -> false
			user.aud != provider.clientId -> false
			user.exp < System.currentTimeMillis() -> false
			else -> true
		}
	}
}