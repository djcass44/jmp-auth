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
import dev.castive.javalin_auth.auth.response.Responses
import dev.castive.javalin_auth.config.OAuth2Config
import dev.castive.javalin_auth.util.ok
import dev.castive.log2.Log
import dev.castive.log2.loge
import dev.castive.log2.logi
import dev.castive.log2.logv
import dev.dcas.util.extend.json
import io.javalin.apibuilder.ApiBuilder
import io.javalin.apibuilder.EndpointGroup
import io.javalin.http.BadRequestResponse
import io.javalin.http.Context
import io.javalin.http.NotFoundResponse
import org.eclipse.jetty.http.HttpStatus

class OAuth2(private val baseUrl: String, private val callback: Callback, private val config: Map<String, OAuth2Config>): EndpointGroup {
	companion object {
		val providers = hashMapOf<String, AbstractOAuth2Provider>()
	}

	data class TokenResponse(val request: String, val refresh: String, val source: String? = null)

	abstract class Callback {
		fun createUser(token: OAuth2AccessToken, provider: AbstractOAuth2Provider): Boolean = createUser(token.accessToken, token.refreshToken ?: token.accessToken, provider)
		abstract fun createUser(accessToken: String, refreshToken: String, provider: AbstractOAuth2Provider): Boolean
	}

	init {
		registerProvider("github")
		registerProvider("google")
		"Enabled ${providers.size} OAuth2 providers".logi(javaClass)
		"Active OAuth2 providers: ${providers.keys.toTypedArray().contentToString()}".logi(javaClass)
	}

	/**
	 * Get an OAuth2 configuration or throw an error
	 */
	private fun registerProvider(name: String) {
		val config = config[name] ?: run {
			"Failed to locate config for $name, it will not be enabled".logv(javaClass)
			return
		}
		if(config.enabled) {
			when(name) {
				"github" -> GitHubProvider(config)
				"google" -> GoogleProvider(config)
				else -> null
			}?.let {
				// add the provider
				providers[name] = it
			}
		}
	}


	override fun addEndpoints() {
		/**
		 * Check whether a provider exists
		 * Used by the front end for showing social login buttons
		 */
		ApiBuilder.get("$baseUrl/o2/api/:name", { ctx ->
			val oauth = getProvider(ctx)
			ctx.ok().result(oauth.sourceName)
		}, Roles.openAccessRole)
		/**
		 * Use the consent code to get a session from the Oauth provider
		 */
		ApiBuilder.get("$baseUrl/o2/callback", { ctx ->
			// do something with the response
			Log.d(javaClass, "query: ${ctx.queryString()}, path: ${ctx.path()}")
			val code = ctx.queryParam("code", String::class.java).getOrNull()
			if (code == null) {
				// We couldn't get the code from the consent callback
				Log.e(javaClass, "Failed to get code from callback query: ${ctx.queryString()}")
				throw BadRequestResponse("Could not find 'code' query parameter")
			}
			val state = ctx.queryParam("state", String::class.java).getOrNull() ?: run {
				// We couldn't get the state from the consent callback
				"Failed to get state from callback query: ${ctx.queryString()}".loge(javaClass)
				throw BadRequestResponse("Could not find 'state' query parameter")
			}
			val (name, _, _) = AbstractOAuth2Provider.parseState(state)
			"Got callback request for provider: '$name'".logv(javaClass)
			// get the provider
			val provider = runCatching {
				providers[name]
			}.getOrNull() ?: throw NotFoundResponse("Could not find provider: $name")
			val token = try {
				provider.getAccessToken(code)
			}
			catch (e: Exception) {
				"Failed to extract access token from code: $e".loge(javaClass)
				throw BadRequestResponse("Unable to extract access token")
			}
			Log.d(javaClass, token.json())
			// Attempt to create the user
			if (callback.createUser(token, provider))
				ctx.status(HttpStatus.OK_200).json(
					TokenResponse(
						token.accessToken,
						token.refreshToken ?: token.accessToken,
						provider.sourceName
					)
				)
			else {
				"Failed to create user from token: ${token.accessToken}".loge(javaClass)
				ctx.status(HttpStatus.INTERNAL_SERVER_ERROR_500)
			}
		}, Roles.openAccessRole)
		/**
		 * Redirect the user to an oauth2 provider consent screen
		 * No handling is done here, that is done by the callback
		 * Note: the user will hit this endpoint directly
		 */
		ApiBuilder.get("$baseUrl/o2/:name", { ctx ->
			val oauth = getProvider(ctx)
			// get the url from the actual provider
			val url = oauth.getAuthoriseUrl()
			ctx.ok().json(oauth.sourceName to url)
		}, Roles.openAccessRole)
		/**
		 * Invalidate a users token
		 */
		ApiBuilder.post("$baseUrl/o2/logout/:name", { ctx ->
			val token = ctx.queryParam("accessToken", String::class.java, null).getOrNull() ?: throw BadRequestResponse(
				"Invalid access token"
			)
			val provider = getProvider(ctx)
			Log.a(javaClass, "Logging out user with accessToken: $token")
			// Sometimes revoking the token is unsupported and throws an exception
			// This is okay and we still want to return the 200
			try {
				provider.revokeTokenAsync(token)
			}
			catch (e: Exception) {
				Log.e(javaClass, "Failed to logout: $e")
			}
			ctx.ok().result("OK")
		}, Roles.defaultAccessRole)
	}
	private fun getProvider(ctx: Context): AbstractOAuth2Provider {
		val provider = ctx.pathParam("name", String::class.java).getOrNull() ?: throw BadRequestResponse("Invalid provider")
		return runCatching {
			providers[provider]
		}.getOrNull() ?: throw NotFoundResponse(Responses.NOT_FOUND_PROVIDER)
	}
}