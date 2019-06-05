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
import dev.castive.javalin_auth.auth.connect.CrowdConfig
import dev.castive.javalin_auth.auth.data.Group
import dev.castive.javalin_auth.auth.data.User
import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.AuthenticateRequest
import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.AuthenticateResponse
import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.GroupSearch
import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.UserSearch
import dev.castive.javalin_auth.util.Util
import dev.castive.log2.Log

class CrowdProvider(private val config: CrowdConfig): BaseProvider {
	companion object {
		const val SOURCE_NAME = "Crowd"
	}
	private val gson = GsonBuilder().setPrettyPrinting().create()
	override fun setup() {
		FuelManager.instance.apply {
			basePath = config.crowdUrl
			baseHeaders = mapOf(
				Pair("Authorization", Util.basicAuth(config.appAuth.username, config.appAuth.password)),
				Pair("Content-Type", "application/json"),
				Pair("Accept", "application/json")
			)
		}
	}

	override fun tearDown() {

	}

	// Get all the users we can
	// Currently only supports the 1st 1000 groups
	override fun getUsers(): ArrayList<User> {
		val users = arrayListOf<User>()
		val params = listOf(
			Pair("entity-type", "user")
		)
		val r = FuelManager.instance.get("/rest/usermanagement/1/search", params)
			.responseObject { _: Request, _: Response, result: Result<UserSearch, FuelError> ->
				when(result) {
					is Result.Failure -> {
						Log.e(javaClass, "Failed to load groups, ${result.getException().exception}")
					}
					is Result.Success -> {
						val data = result.get()
						data.users.forEach {
							Log.v(javaClass, "Found $SOURCE_NAME users: ${it.name}")
							users.add(User(it.name, it.name, "", SOURCE_NAME))
						}
						Log.i(javaClass, "Loaded ${users.size} user from $SOURCE_NAME")
					}
				}
			}
		r.join()
		return users
	}

	// Get all the groups we can
	// Currently only supports the 1st 1000 groups
	override fun getGroups(): ArrayList<Group> {
		val groups = arrayListOf<Group>()
		val params = listOf(
			Pair("entity-type", "group")
		)
		val r = FuelManager.instance.get("/rest/usermanagement/1/search", params)
			.responseObject { _: Request, _: Response, result: Result<GroupSearch, FuelError> ->
				when(result) {
					is Result.Failure -> {
						Log.e(javaClass, "Failed to load groups, ${result.getException().exception}")
					}
					is Result.Success -> {
						val data = result.get()
						data.groups.forEach {
							Log.v(javaClass, "Found $SOURCE_NAME group: ${it.name}")
							groups.add(Group(it.name, it.name, SOURCE_NAME))
						}
						Log.i(javaClass, "Loaded ${groups.size} groups from $SOURCE_NAME")
					}
				}
			}
		r.join()
		return groups
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
						Log.ok(javaClass, "$SOURCE_NAME created a new session for ${data.user.name}")
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