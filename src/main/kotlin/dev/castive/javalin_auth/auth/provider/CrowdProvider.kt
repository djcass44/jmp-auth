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
import com.google.gson.reflect.TypeToken
import dev.castive.javalin_auth.auth.connect.CrowdConfig
import dev.castive.javalin_auth.auth.data.Group
import dev.castive.javalin_auth.auth.data.User
import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.*
import dev.castive.javalin_auth.util.Util
import dev.castive.log2.Log

class CrowdProvider(private val config: CrowdConfig): BaseProvider {
	companion object {
		const val SOURCE_NAME = "Crowd"
	}
	private val gson = GsonBuilder().setPrettyPrinting().create()
	private val userCache = arrayListOf<User>()

	override fun setup() {
		FuelManager.instance.apply {
			basePath = config.crowdUrl
			baseHeaders = mapOf(
				Pair("Authorization", Util.basicAuth(config.serviceAccount.username, config.serviceAccount.password)),
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
		userCache.clear()
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
							userCache.add(User(it.name, it.name, "", SOURCE_NAME))
						}
						Log.i(javaClass, "Loaded ${userCache.size} user from $SOURCE_NAME")
					}
				}
			}
		r.join()
		return userCache
	}

	// Get all the groups we can
	// Currently only supports the 1st 1000 groups
	override fun getGroups(): ArrayList<Group> {
		if(userCache.size == 0) getUsers()
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
							groups.add(addGroupUsers(Group(it.name, it.name, SOURCE_NAME)))
						}
						Log.i(javaClass, "Loaded ${groups.size} groups from $SOURCE_NAME")
					}
				}
			}
		r.join()
		return groups
	}

	// This can probably be improved
	private fun addGroupUsers(group: Group): Group {
		val members = arrayListOf<User>()
		val params = listOf(
			Pair("groupname", group.name)
		)
		val r = FuelManager.instance.get("/rest/usermanagement/1/group/user/direct", params)
			.responseObject { _: Request, _: Response, result: Result<UserSearch, FuelError> ->
				when(result) {
					is Result.Failure -> {
						Log.e(javaClass, "Failed to get direct members of group: ${group.name}, ${result.getException().exception}")
					}
					is Result.Success -> {
						val data = result.get()
						val names = arrayListOf<String>()
						data.users.forEach {
							names.add(it.name)
						}
						Log.d(javaClass, "Found ${data.users.size} users in group: ${group.name}")
						userCache.forEach { if(names.contains(it.username)) members.add(it) }
					}
				}
			}
		r.join()
		return Group(group.name, group.dn, members, group.source)
	}

	override fun userInGroup(group: Group, user: User): Boolean {
		var res = false
		val params = listOf(
			Pair("username", user.username),
			Pair("groupname", group.name)
		)
		val r = FuelManager.instance.get("/rest/usermanagement/1/user/group/direct", params)
			.responseObject { _: Request, _: Response, result: Result<Groups, FuelError> ->
				when(result) {
					is Result.Failure -> {
						Log.e(javaClass, "Failed to check membership, or the user isn't a member, ${result.getException().exception}")
						res = false
					}
					is Result.Success -> {
						val data = result.get()
						Log.d(javaClass, data.toString())
						res = data.name == group.name
						Log.i(javaClass, "${user.username} in ${group.name}: $res")
					}
				}
			}
		r.join()
		return res
	}

	override fun getLogin(uid: String, password: String, data: Any?): String? {
		val factors = if(data == null || data !is String) {
			Log.w(javaClass, "Not sending validation factors, this may cause login issues")
			null
		}
		else {
			// This is very sketchy
			Log.d(javaClass, "getLogin received data: $data")
			ValidationFactors(gson.fromJson(data, object : TypeToken<List<Factor>>() {}.type))
		}
		var token: String? = null
		val r = FuelManager.instance.post("/rest/usermanagement/1/session")
			.body(gson.toJson(AuthenticateRequest(uid, password, factors)))
			.responseObject { _: Request, _: Response, result: Result<AuthenticateResponse, FuelError> ->
				token = when(result) {
					is Result.Failure -> {
						Log.e(javaClass, "Failed to authenticate $uid, ${result.getException().exception}")
						null
					}
					is Result.Success -> {
						val res = result.get()
						Log.ok(javaClass, "$SOURCE_NAME created a new session for ${res.user.name}")
						Log.d(javaClass, "Created session with token: ${res.token}")
						gson.toJson(res)
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
		var res = false
		val r = FuelManager.instance.post("/")
			.responseString { it ->
				Log.d(javaClass, "Crowd connection status: $it")
				res = it.get().isNotBlank()
			}
		r.join()
		return res
	}

	override fun validate(token: String, data: Any): String? {
		var response: String? = null
		val r = FuelManager.instance.post("/rest/usermanagement/1/session/$token")
			.body(gson.toJson(data))
			.responseObject { _: Request, _: Response, result: Result<AuthenticateResponse, FuelError> ->
				response = when(result) {
					is Result.Failure -> {
						Log.e(javaClass, "Failed to validate SSO token: $token, ${result.getException().exception}")
						null
					}
					is Result.Success -> {
						val res = result.get()
						Log.ok(javaClass, "Validated SSO token for ${res.user.name}")
						// Probably not needed, but just in case
						gson.toJson(res)
					}
				}
			}
		r.join()
		return response
	}

	override fun getSSOConfig(): Any? {
		var response: Any? = null
		val r = FuelManager.instance.get("/rest/usermanagement/1/config/cookie")
			.responseObject { _: Request, _: Response, result: Result<CrowdCookieConfig, FuelError> ->
				response = when(result) {
					is Result.Failure -> {
						Log.e(javaClass, "Failed to get cookie config:, ${result.getException().exception}")
						null
					}
					is Result.Success -> {
						val res = result.get()
						Log.ok(javaClass, "Got cookie config $res")
						res
					}
				}
			}
		r.join()
		return response
	}

	override fun invalidateLogin(id: String) {
		val r = FuelManager.instance.delete("/rest/usermanagement/1/session/${id}")
			.responseString { it ->
				Log.i(javaClass, "Invalidated token: $id, response: ${it.get()}")
			}
		r.join()
	}
}