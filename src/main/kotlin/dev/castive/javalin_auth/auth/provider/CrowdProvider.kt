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
import com.google.gson.GsonBuilder
import dev.castive.javalin_auth.auth.data.Group
import dev.castive.javalin_auth.auth.data.User
import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.AuthenticateRequest
import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.AuthenticateResponse
import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.BasicAuthentication
import dev.castive.javalin_auth.util.Util
import dev.castive.log2.Log

class CrowdProvider(private val crowdUrl: String, private val appAuth: BasicAuthentication): BaseProvider {
	companion object {
		const val SOURCE_NAME = "Crowd"
	}
	private val gson = GsonBuilder().setPrettyPrinting().create()
	override fun setup() {
		FuelManager.instance.apply {
			basePath = crowdUrl
			baseHeaders = mapOf(
				Pair("Authorization", Util.basicAuth(appAuth.username, appAuth.password)),
				Pair("Content-Type", "application/json"),
				Pair("Accept", "application/json")
			)
		}
	}

	override fun tearDown() {
		TODO("not implemented")
	}

	override fun getUsers(): ArrayList<User> {
		TODO("not implemented")
	}

	override fun getGroups(): ArrayList<Group> {
		TODO("not implemented")
	}

	override fun userInGroup(group: Group, user: User): Boolean {
		TODO("not implemented")
	}

	override fun getLogin(uid: String, password: String): String? {
		var token: String? = null
		val r = FuelManager.instance.post("/rest/usermanagement/1/session")
			.body(gson.toJson(AuthenticateRequest(uid, password)))
			.responseObject { _: Request, _: Response, result: Result<AuthenticateResponse, FuelError> ->
				token = when(result) {
					is Result.Failure -> {
						Log.e(javaClass, "Failed to authenticate $uid, ${result.getException().exception}")
						null
					}
					is Result.Success -> {
						val data = result.get()
						Log.ok(javaClass, "Crowd created a new session for ${data.user.name}")
						Log.d(javaClass, "Created session with token: ${data.token}")
						data.token
					}
				}
			}
		r.join()
		return token
	}

	override fun getName(): String {
		return SOURCE_NAME
	}

	override fun connected(): Boolean {
		TODO("not implemented")
	}

	override fun validate(token: String, data: Any): Boolean {
		var response = false
		val r = FuelManager.instance.post("/rest/usermanagement/1/session/$token")
			.body(gson.toJson(data))
			.responseObject { _: Request, _: Response, result: Result<AuthenticateResponse, FuelError> ->
				response = when(result) {
					is Result.Failure -> {
						Log.e(javaClass, "Failed to validate SSO token: $token, ${result.getException().exception}")
						false
					}
					is Result.Success -> {
						val res = result.get()
						Log.ok(javaClass, "Validated SSO token for ${res.user.name}")
						// Probably not needed, but just in case
						(res.token == token)
					}
				}
			}
		r.join()
		return response
	}
}