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

import dev.castive.javalin_auth.auth.connect.CrowdConfig
import dev.castive.javalin_auth.auth.data.Group
import dev.castive.javalin_auth.auth.data.User
import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.BasicAuthentication
import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.Factor
import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.ValidateRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class CrowdProviderTest {
	private val config = CrowdConfig(
		crowdUrl = "http://localhost:8095/crowd",
		appAuth = BasicAuthentication("jmp", "password"),
		serviceAccount = BasicAuthentication("SVC_Crowd", "crowd")
	)

	private val provider = CrowdProvider(config)

	@BeforeEach
	internal fun setUp() {
		provider.setup()
	}

	@AfterEach
	internal fun tearDown() {
		provider.tearDown()
	}

	@Test
	fun tryLogin() {
		val token = provider.getLogin("django", "djangodjango")!!
		// Disable "Require consistent client IP address" in Crowd for this to pass
		assert(provider.validate(token, ValidateRequest(arrayOf(Factor("remote_address", "127.0.0.1")))))
	}
	@Test
	fun failLogin() {
		val token = provider.getLogin("django", "djangodjangodjango")
		assert(token == null)
	}
	@Test
	fun loadGroups() {
		val groups = provider.getGroups()
		assert(groups.size > 0)
	}
	@Test
	fun loadUsers() {
		val users = provider.getUsers()
		assert(users.size > 0)
	}
	@Test
	fun checkUserInGroup() {
		val user = User("tony.stark", "", "", CrowdProvider.SOURCE_NAME)
		val group = Group("JMP Users", "", CrowdProvider.SOURCE_NAME)
		assert(provider.userInGroup(group, user))
	}
	@Test
	fun checkUserNotInGroup() {
		val user = User("tony.stark", "", "", CrowdProvider.SOURCE_NAME)
		val group = Group("crowd-administrators", "", CrowdProvider.SOURCE_NAME)
		assert(!provider.userInGroup(group, user))
	}
	@Test
	fun checkCrowdConnected() {
		assert(provider.connected())
	}
}