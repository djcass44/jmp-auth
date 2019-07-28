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

import dev.castive.javalin_auth.auth.data.Group
import dev.castive.javalin_auth.auth.data.User
import dev.castive.log2.Log
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class AzureProviderTest {
	private val provider = AzureProvider()

	@BeforeEach
	internal fun setUp() {
		provider.setup()
	}

	@AfterEach
	internal fun tearDown() {
		provider.tearDown()
	}

	@Test
	fun getUsers() {
		val users = provider.getUsers()
		Log.d(javaClass, "Found ${users.size} users")
		assert(users.size > 0)
	}
	@Test
	fun getGroups() {
		val groups = provider.getGroups()
		Log.d(javaClass, "Found ${groups.size} groups")
		assert(groups.size > 0)
		groups.forEach {
			Log.d(javaClass, "${it.name}: ${it.members.size}")
		}
	}
	@Test
	fun getUserInGroup() {
		val userDn = "cn=Django Cass,ou=Admins,ou=TestUnit,dc=example,dc=org"
		val groupDn = "cn=Users,ou=TestUnit,dc=example,dc=org"
		val inGroup = provider.userInGroup(Group("Admin2", groupDn, ""), User("dcass", userDn, "", ""))
		Log.d(javaClass, "User [$userDn] in group [$groupDn]: $inGroup")
		assert(inGroup)
	}
}