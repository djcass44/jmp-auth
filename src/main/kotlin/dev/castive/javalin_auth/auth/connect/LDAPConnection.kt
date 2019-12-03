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

package dev.castive.javalin_auth.auth.connect

import dev.castive.javalin_auth.config.LDAP2Config
import dev.castive.log2.loge
import dev.castive.log2.logi
import dev.castive.log2.logv
import dev.castive.log2.logw
import java.util.*
import javax.naming.Context
import javax.naming.directory.DirContext
import javax.naming.directory.InitialDirContext
import javax.naming.directory.SearchControls
import javax.naming.directory.SearchResult

class LDAPConnection(private val config: LDAP2Config) {

	private fun ldapContext(env: Hashtable<String, String>): DirContext {
		env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
		env[Context.PROVIDER_URL] = "ldap://${config.url}:${config.port}/"
		return InitialDirContext(env)
	}

	/**
	 * Locate a user object in the directory
	 */
	fun search(username: String): SearchResult? {
		val env = if(config.username.isNotBlank() && config.password.isNotBlank()) {
			Hashtable<String, String>(mutableMapOf(
				Context.SECURITY_AUTHENTICATION to "simple",
				Context.SECURITY_PRINCIPAL to config.username,
				Context.SECURITY_CREDENTIALS to config.password
			))
		}
		else {
			"Username or password is blank, attempting anonymous binding".logw(javaClass)
			Hashtable(mutableMapOf(
				Context.SECURITY_AUTHENTICATION to "none"
			))
		}
		val ctx = try {
			ldapContext(env)
		}
		catch (e: Exception) {
			"Failed to establish LDAP connection: $e".loge(javaClass)
			return null
		}

		val filter = "(${config.uidField}=$username)"
		val ctrl = SearchControls().apply {
			searchScope = SearchControls.SUBTREE_SCOPE
		}
		val answer = ctx.search(config.contextDN, filter, ctrl)

		return if (answer.hasMore()) {
			val result = answer.next()
			result
		}
		else null
	}

	/**
	 * Get a users DN from a uid
	 */
	fun getDN(user: String): String? = search(user)?.nameInNamespace

	fun checkUserAuth(username: String, password: String): Boolean {
		val dn = getDN(username) ?: run {
			"Could not find DN for user: $username".logi(javaClass)
			return false
		}
		return bindUser(dn, password)
	}

	/**
	 * Attempt to create a bind using the users credentials
	 * If we cannot create the bind, the provided credentials must be invalid
	 * @return false if credentials are invalid or there was an error connecting
	 */
	fun bindUser(dn: String, password: String): Boolean {
		val env = Hashtable<String, String>(mutableMapOf(
			Context.SECURITY_AUTHENTICATION to "simple",
			Context.SECURITY_PRINCIPAL to dn,
			Context.SECURITY_CREDENTIALS to password
		))
		return try {
			ldapContext(env)
			true
		}
		catch (e: Exception) {
			"Failed to bind user [$dn]: $e".logv(javaClass)
			false
		}
	}
}