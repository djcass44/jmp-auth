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
 */

package dev.castive.javalin_auth.auth.provider

import dev.castive.javalin_auth.auth.connect.LDAPConfig2
import dev.castive.javalin_auth.auth.connect.LDAPConnection
import dev.castive.javalin_auth.auth.data.Group
import dev.castive.javalin_auth.auth.data.User
import dev.castive.javalin_auth.auth.external.UserVerification
import dev.castive.log2.Log
import java.util.*
import javax.naming.AuthenticationException
import javax.naming.NamingException

class LDAPProvider(private val config: LDAPConfig2,
                          private val verification: UserVerification?): BaseProvider {
	companion object {
		const val SOURCE_NAME = "ldap"
	}
	private lateinit var connection: LDAPConnection

	private val userCache = arrayListOf<User>()

	private var connected = false

	override fun setup() = try {
		connection = LDAPConnection(config.baseConfig, reconnectOnLogin = config.extraConfig.reconnectOnAuth, serviceAccount = config.serviceAccount)
		connected = connection.connected
		Log.i(javaClass, "LDAP connected: $connected")
	}
	catch (e: AuthenticationException) {
		connected = false
		Log.e(javaClass, "LDAP -> Wrong authentication")
	}
	catch (e: NamingException) {
		connected = false
		Log.e(javaClass, "LDAP -> Couldn't connect: $e")
	}

	override fun tearDown() {
		connection.close()
	}

	override fun getUsers(): ArrayList<User> {
		userCache.clear()
		val result = connection.searchFilter(config.extraConfig.userFilter) ?: return arrayListOf()
		for (r in result) {
			Log.d(javaClass, r.attributes.toString())
			val username = kotlin.runCatching { r.attributes.get(config.extraConfig.uid).get(0).toString() }.getOrNull()
			if(username == null) {
				Log.e(javaClass, "Failed to read name of user, dumping attributes for manual fix: ${runCatching { return@runCatching r.attributes }}")
				continue
			}
			Log.d(javaClass, "user: $username")
			val role = kotlin.runCatching { r.attributes.get("objectClass").get(0).toString() }.getOrNull()
			if(role == null) {
				Log.e(javaClass, "Failed to read objectClass of user, dumping attributes for manual fix: ${runCatching { return@runCatching r.attributes }}")
				continue
			}
			userCache.add(User(username, r.nameInNamespace, role, SOURCE_NAME))
		}
		return userCache
	}

	private fun getUserWithDn(dn: String): User? {
		userCache.forEach {
			if(it.dn == dn) return it
		}
		return null
	}

	override fun getGroups(): ArrayList<Group> {
		if(userCache.isEmpty()) getUsers()
		val groups = arrayListOf<Group>()
		val result = connection.searchFilter(config.groupConfig.groupFilter) ?: return groups
		for (r in result) {
			Log.d(javaClass, r.attributes.toString())
			val name = kotlin.runCatching { r.attributes.get(config.groupConfig.gid).get(0).toString() }.getOrNull()
			if(name == null) {
				Log.e(javaClass, "Failed to read name of group, dumping attributes for manual fix: ${runCatching { return@runCatching r.attributes }}")
				continue
			}
			// Get the users in the group
			val members = kotlin.runCatching { r.attributes.get("member").all }.getOrNull()
			if(members == null) {
				Log.e(javaClass, "Failed to read member attribute of group, dumping attributes for manual fix: ${runCatching { return@runCatching r.attributes }}")
				continue
			}
			val users = arrayListOf<User>()
			while (members.hasMore()) {
				val m = members.next().toString()
				val user = getUserWithDn(m)
				if(user != null) users.add(user)
			}
			groups.add(Group(name, r.nameInNamespace, users, SOURCE_NAME))
		}
		return groups
	}

	override fun userInGroup(group: Group, user: User): Boolean {
		val filter = "(&${config.groupConfig.groupFilter}(${config.groupConfig.groupQuery}=${user.dn}))"
		Log.d(javaClass, "Using filter: $filter")
		val res = connection.searchFilter(filter) ?: run {
			Log.d(javaClass, "Search returned null")
			return false
		}
		Log.d(javaClass, "Search is size: ${res.size}")
		res.forEach {
			Log.d(javaClass, "r: ${it.attributes}, name: ${it.nameInNamespace}")
			val dn = it.nameInNamespace
			if(dn == group.dn) {
				val members = kotlin.runCatching { it.attributes.get("member").all }.getOrNull()
				if(members == null) Log.e(javaClass, "Failed to read name of group, dumping attributes for manual fix: ${runCatching { return@runCatching it.attributes }}")
				else {
					while (members.hasMore()) {
						val m = members.next().toString()
						Log.d(javaClass, "member: $m")
						if (m == user.dn) return true
					}
				}
			}
		}
		return false
	}

	override fun getLogin(uid: String, password: String): String? {
		val valid = connection.checkUserAuth(uid, password, config.extraConfig.uid)
		return if (valid) verification?.getToken(uid)
		else null
	}

	override fun getName(): String {
		return SOURCE_NAME
	}

	override fun connected(): Boolean {
		return connection.connected
	}

	override fun validate(token: String, data: Any) = true
}