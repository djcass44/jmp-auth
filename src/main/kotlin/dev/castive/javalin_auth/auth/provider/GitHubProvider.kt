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

import com.github.kittinunf.fuel.gson.responseObject
import com.github.kittinunf.fuel.httpGet
import com.github.scribejava.apis.GitHubApi
import dev.castive.javalin_auth.auth.data.User2
import dev.castive.javalin_auth.auth.data.model.github.GitHubUser
import dev.castive.javalin_auth.auth.provider.flow.AbstractOAuth2Provider
import dev.castive.javalin_auth.auth.provider.flow.BaseFlow
import dev.castive.javalin_auth.config.OAuth2Config
import dev.castive.log2.Log
import dev.dcas.util.extend.toBasic
import org.eclipse.jetty.http.HttpStatus

@Suppress("unused")
class GitHubProvider(config: OAuth2Config): AbstractOAuth2Provider(
	BaseFlow(
		authorizeUrl = "https://github.com/login/oauth/authorize",
		apiUrl = "https://api.github.com",
		callbackUrl = config.callbackUrl,
		scope = "read:user",
		clientId = config.clientId,
		clientSecret = config.clientSecret,
		api = GitHubApi.instance()
	)
) {
	override val sourceName: String
		get() = "github"

	/**
	 * Check if the access token is still valid
	 */
	override fun isTokenValid(accessToken: String, data: Any?): Boolean {
		val (_, response, result) = "${provider.apiUrl}/applications/${provider.clientId}/tokens/$accessToken".httpGet().appendHeader("Authorization", (provider.clientId to provider.clientSecret).toBasic()).responseString()
		val code = response.statusCode
		Log.d(javaClass, "Got response code: $code")
		Log.d(javaClass, "Got response body: ${result.component1()}")
		// 200 means that token is OK, 400 is invalid
		return code == HttpStatus.OK_200
	}

	/**
	 * Get the information required to create a user
	 */
	override fun getUserInformation(accessToken: String): User2? {
		val (_, response, result) = "${provider.apiUrl}/user".httpGet().appendHeader("Authorization", "token $accessToken").responseObject<GitHubUser>()
		if(response.statusCode != 200) {
			Log.e(javaClass, "Failed to load user information: ${result.component2()?.exception}")
			return null
		}
		// Assume nothing else has gone wrong
		return User2(result.get())
	}
}