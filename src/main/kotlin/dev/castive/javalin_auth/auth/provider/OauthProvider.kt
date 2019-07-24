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

import com.github.scribejava.apis.GitHubApi
import com.github.scribejava.core.builder.ServiceBuilder
import dev.castive.javalin_auth.auth.data.Group
import dev.castive.javalin_auth.auth.data.User
import dev.castive.log2.Log
import dev.castive.securepass3.PasswordGenerator
import io.javalin.Context
import io.javalin.apibuilder.ApiBuilder.get
import io.javalin.apibuilder.ApiBuilder.post
import io.javalin.apibuilder.EndpointGroup

class OauthProvider: BaseProvider {
	companion object {
		const val SOURCE_NAME = "oauth2"

		private const val apiUrl = "https://github.com/login/oauth/authorize"
		private const val apiScope = "read:user"

		private const val clientId = ""
		private const val clientSecret = ""
	}
	private val generator = PasswordGenerator()

	private val service = ServiceBuilder(clientId)
		.apiSecret(clientSecret)
		.callback("http://localhost:7000/oauth2callback")
		.defaultScope(apiScope)
		.build(GitHubApi.instance())

	override fun setup() {}

	override fun tearDown() {}

	override fun getUsers(): ArrayList<User> {
		return arrayListOf()
	}

	override fun getGroups(): ArrayList<Group> {
		return arrayListOf()
	}

	override fun userInGroup(group: Group, user: User): Boolean {
		return false
	}

	override fun getLogin(uid: String, password: String, data: Any?): String? {
		val url = service.getAuthorizationUrl(generator.generate(32).toString())
		Log.d(javaClass, "Auth url: $url")
		return null
	}

	override fun getName(): String {
		return SOURCE_NAME
	}

	override fun connected(): Boolean {
		return true
	}

	override fun validate(token: String, data: Any): String? = "OK"

	override fun getSSOConfig(): Any? = null

	override fun invalidateLogin(id: String) {}

	override fun hasUser(ctx: Context): Pair<User?, BaseProvider.TokenContext?> {
		return Pair(null, null)
	}

	fun getCallbackRoute(): EndpointGroup {
		return EndpointGroup {
			get("/oauth2callback") { ctx ->
				respondToCallback(ctx)
			}
			post("/oauth2callback") { ctx ->
				respondToCallback(ctx)
			}
		}
	}

	private fun respondToCallback(ctx: Context) {
		Log.a(javaClass, "Oauth2 callback")
	}
}