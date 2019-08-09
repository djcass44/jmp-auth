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

package dev.castive.javalin_auth.api

import com.github.scribejava.core.model.OAuth2AccessToken
import dev.castive.javalin_auth.auth.Roles
import dev.castive.javalin_auth.auth.provider.GitHubProvider
import dev.castive.javalin_auth.auth.provider.GoogleProvider
import dev.castive.javalin_auth.auth.provider.flow.AbstractOAuth2Provider
import dev.castive.javalin_auth.util.EnvUtil
import dev.castive.javalin_auth.util.Util
import dev.castive.log2.Log
import io.javalin.apibuilder.ApiBuilder
import io.javalin.apibuilder.EndpointGroup
import io.javalin.http.BadRequestResponse
import io.javalin.http.Context
import io.javalin.http.NotFoundResponse
import org.eclipse.jetty.http.HttpStatus
import java.util.*

class OAuth2(private val baseUrl: String, private val callback: Callback): EndpointGroup {
	companion object {
		val providers = hashMapOf<String, AbstractOAuth2Provider>()
		init {
			if(EnvUtil.getEnv(EnvUtil.GITHUB_ENABLED) == "true") providers["github"] = GitHubProvider()
			if(EnvUtil.getEnv(EnvUtil.GOOGLE_ENABLED) == "true") providers["google"] = GoogleProvider()
			Log.i(OAuth2::class.java, "Enabled ${providers.size} OAuth2 providers")
			Log.i(OAuth2::class.java, "Active OAuth2 providers: ${Arrays.toString(providers.keys.toTypedArray())}")
		}
	}
	data class TokenResponse(val request: String, val refresh: String, val source: String? = null)
	abstract class Callback {
		fun createUser(token: OAuth2AccessToken, provider: AbstractOAuth2Provider): Boolean = createUser(token.accessToken, token.refreshToken ?: token.accessToken, provider)
		abstract fun createUser(accessToken: String, refreshToken: String, provider: AbstractOAuth2Provider): Boolean
	}
	override fun addEndpoints() {
		/**
		 * Check whether a provider exists
		 * Used by the front end for showing social login buttons
		 */
		ApiBuilder.head("$baseUrl/v2/oauth2/authorise", { ctx ->
			val oauth = getProvider(ctx)
			ctx.status(HttpStatus.OK_200).result(oauth.sourceName)
		}, Roles.openAccessRole)
		/**
		 * Redirect the user to an oauth2 provider consent screen
		 * No handling is done here, that is done by the callback
		 * Note: the user will hit this endpoint directly
		 */
		ApiBuilder.get("$baseUrl/v2/oauth2/authorise", { ctx ->
			val oauth = getProvider(ctx)
			// get the url from the actual provider
			val url = oauth.getAuthoriseUrl()
			ctx.redirect(url, HttpStatus.FOUND_302)
		}, Roles.openAccessRole)
		/**
		 * Use the consent code to get a session from the Oauth provider
		 */
		ApiBuilder.get("$baseUrl/v2/oauth2/callback", { ctx ->
			// do something with the response
			Log.d(javaClass, "query: ${ctx.queryString()}, path: ${ctx.path()}")
			val code = ctx.queryParam("code", String::class.java).getOrNull()
			if (code == null) {
				// We couldn't get the code from the consent callback
				Log.e(javaClass, "Failed to get code from callback query: ${ctx.queryString()}")
				throw BadRequestResponse("Could not find 'code' query parameter")
			}
			val provider =
				ctx.header("X-Auth-Source") ?: throw BadRequestResponse("Please set the X-Auth-Source header")
			Log.i(javaClass, "Got provider from header [X-Auth-Source]: $provider")
			val oauth = kotlin.runCatching { providers[provider] }.getOrNull()
				?: throw NotFoundResponse("That provider could not be found.")
			val token = oauth.getAccessToken(code)
			Log.d(javaClass, Util.gson.toJson(token))
			// Attempt to create the user
			if (callback.createUser(token, oauth))
				ctx.status(HttpStatus.OK_200).json(
					TokenResponse(
						token.accessToken,
						token.refreshToken ?: token.accessToken,
						oauth.sourceName
					)
				)
			else {
				Log.e(javaClass, "Failed to create user from token: ${token.accessToken}")
				ctx.status(HttpStatus.INTERNAL_SERVER_ERROR_500)
			}
		}, Roles.openAccessRole)
		/**
		 * Invalidate a users token
		 */
		ApiBuilder.post("$baseUrl/v2/oauth2/logout", { ctx ->
			val token = ctx.queryParam("accessToken", String::class.java, null).getOrNull() ?: throw BadRequestResponse(
				"Invalid access token"
			)
			val oauth = getProvider(ctx)
			Log.a(javaClass, "Logging out user with accessToken: $token")
			oauth.revokeTokenAsync(token)
			ctx.status(HttpStatus.OK_200)
		}, Roles.defaultAccessRole)
	}
	private fun getProvider(ctx: Context): AbstractOAuth2Provider {
		val provider = ctx.queryParam("provider", String::class.java).getOrNull() ?: throw BadRequestResponse("Invalid provider")
		return kotlin.runCatching { providers[provider] }.getOrNull() ?: throw NotFoundResponse("That provider could not be found.")
	}
}