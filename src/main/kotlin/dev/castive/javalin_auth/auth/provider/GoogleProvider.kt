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
import dev.castive.javalin_auth.util.EnvUtil
import dev.castive.javalin_auth.util.Util
import dev.castive.log2.Log

@Suppress("unused")
class GoogleProvider: AbstractOAuth2Provider(
	BaseFlow(
		authorizeUrl = "www.googleapis.com/oauth2/v4/token",
		apiUrl = "https://www.googleapis.com/oauth2",
		callbackUrl = EnvUtil.getEnv(EnvUtil.GOOGLE_CALLBACK),
		scope = "profile",
		clientId = EnvUtil.getEnv(EnvUtil.GOOGLE_CLIENT_ID),
		clientSecret = EnvUtil.getEnv(EnvUtil.GOOGLE_CLIENT_SECRET),
		api = GoogleApi20.instance()
	)
) {
	override val sourceName: String
		get() = "google"

	override fun isTokenValid(accessToken: String): Boolean {
		return true
	}

	override fun getUserInformation(accessToken: String): User2? {
		// Create an sign the request
		val request = OAuthRequest(Verb.GET, "${flow.apiUrl}/v3/userinfo")
		service.signRequest(accessToken, request)
		val response = service.execute(request)
		// If the request failed, return null
		if(!response.isSuccessful) {
			Log.e(javaClass, "Failed to load user information: ${response.body}, ${response.message}")
			return null
		}
		Log.d(javaClass, "Got response from google: ${response.body}")
		val res = Util.gson.fromJson(response.body, GoogleUser::class.java)
		return if(validateTokenResponse(res))
			User2(res)
		else
			null
	}

	/**
	 * Check that an ID token is valid
	 * https://developers.google.com/identity/protocols/OpenIDConnect#validatinganidtoken
	 */
	private fun validateTokenResponse(user: GoogleUser): Boolean {
		if(user.iss != "https://accounts.google.com" && user.iss != "accounts.google.com") {
			Log.a(javaClass, "Processed token with iss: ${user.iss}")
			return false
		}
		if(user.aud != flow.clientId) {
			Log.a(javaClass, "Processed token with aud: ${user.aud}")
			return false
		}
		if(user.exp < System.currentTimeMillis()) {
			Log.w(javaClass, "Processed token with exp: ${user.exp}, versus: ${System.currentTimeMillis()}")
			return false
		}

		return true
	}
}