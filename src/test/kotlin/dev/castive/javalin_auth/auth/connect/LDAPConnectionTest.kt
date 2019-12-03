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

package dev.castive.javalin_auth.auth.connect

import dev.castive.javalin_auth.config.LDAP2Config
import org.hamcrest.CoreMatchers.`is`
import org.hamcrest.MatcherAssert.assertThat
import org.junit.jupiter.api.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LDAPConnectionTest {
	private val config = LDAP2Config(
		true,
		"localhost",
		389,
		"dc=example,dc=org",
		"uid",
		"cn=admin,dc=example,dc=org",
		"admin"
	)
	private val configAnon = LDAP2Config(
		true,
		"localhost",
		389,
		"dc=example,dc=org",
		"uid",
		"",
		""
	)

	@Test
	fun `get DN from uid`() {
		val connection = LDAPConnection(config)
		assertThat(connection.getDN("tstark"), `is`("cn=Tony Stark,dc=example,dc=org"))
	}

	@Test
	fun `get DN from uid anonymously`() {
		val connection = LDAPConnection(configAnon)
		assertThat(connection.getDN("tstark"), `is`("cn=Tony Stark,dc=example,dc=org"))
	}

	@Test
	fun `can bind as user`() {
		val connection = LDAPConnection(config)
		assertTrue(connection.bindUser("cn=Tony Stark,dc=example,dc=org", "arstarst"))
	}

	@Test
	fun `verify basic authentication`() {
		val connection = LDAPConnection(config)
		assertTrue(connection.checkUserAuth("tstark", "arstarst"))
	}

	@Test
	fun `blank password fails`() {
		val connection = LDAPConnection(config)
		assertFalse(connection.checkUserAuth("tstark", ""))
	}
}