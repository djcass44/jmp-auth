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

import dev.castive.javalin_auth.except.MinimalConnectionBreachException
import dev.castive.log2.Log
import java.util.*
import javax.naming.Context
import javax.naming.NamingException
import javax.naming.directory.InitialDirContext
import javax.naming.directory.SearchControls
import javax.naming.directory.SearchResult

class LDAPConnection(private val config: LDAPConfig,
                     private val nested: Boolean = false, private val reconnectOnLogin: Boolean = false) {
	var connected = false
		private set
	private lateinit var connection: InitialDirContext

	init {
		connect()
	}

	/**
	 * Attempt to open an LDAP connection
	 * Note: if there is an existing connection, it will be closed first
	 */
	private fun connect() {
		if(connected) {
			Log.w(javaClass, "Found existing LDAP connection, this will be closed...")
			close()
		}
		val env = Hashtable<String, String>()
		env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
//		env["com.sun.jndi.ldap.connect.pool"] = "false"
		env[Context.PROVIDER_URL] = "ldap://${config.server}:${config.port}/"
		env[Context.SECURITY_PRINCIPAL] = config.serviceUserDN
		env[Context.SECURITY_CREDENTIALS] = config.serviceUserPassword
		try {
			connection = InitialDirContext(env)
			Log.ok(javaClass, "LDAP Authentication success!")
			connected = true
		}
		catch (e: NamingException) {
			Log.e(javaClass, "LDAP Authentication failure: $e")
			connected = false
		}
	}

	private fun reconnect() {
		close()
		connect()
	}

	/**
	 * Attempt to close the LDAP connection
	 */
	fun close() {
		try {
			if(!connected) {
				Log.i(javaClass, "There is no active connection to close!")
				return
			}
			connection.close()
			Log.i(javaClass, "LDAP Connection closed")
			connected = false
		}
		catch (e: NamingException) {
			Log.e(javaClass, "Failed to close LDAP connection")
		}
	}

	/**
	 * Run an arbitrary search
	 */
	fun searchFilter(filter: String, contextDN: String = config.contextDN): ArrayList<SearchResult>? {
		if(!this::connection.isInitialized) {
			Log.d(javaClass, "LDAP connection not ready...")
			return null
		}
		if(nested) throw MinimalConnectionBreachException()
		val controls = SearchControls()
		controls.searchScope = SearchControls.SUBTREE_SCOPE
		val searchResults = connection.search(contextDN, filter, controls)
		return if(searchResults.hasMoreElements()) {
			val results = arrayListOf<SearchResult>()
			while (searchResults.hasMore()) results.add(searchResults.next())
			results
		}
		else arrayListOf()
	}

	/**
	 * Verify that a users credentials are correct
	 * Attempts to create a new LDAP connection and login as that user
	 */
	fun checkUserAuth(uid: String, password: String, identifier: String = "uid"): Boolean {
		if(nested) throw MinimalConnectionBreachException()
		// This is a bad hack and not scalable
		if(reconnectOnLogin) reconnect()
		val user = searchFilter("($identifier=$uid)")
//        Log.d(javaClass, "Found user: $user")
		if(user == null || user.size == 0 || user.size > 1) return false  // There must be only 1 user with a uid
		val dn = user[0].nameInNamespace

		val userConfig = LDAPConfig(true, config.server, config.port, config.contextDN, dn, password)

		// Open a new connection with the users creds
		val verifyConnection = LDAPConnection(userConfig, nested = true)
		val connect = verifyConnection.connected
		Log.i(javaClass, "User credential validation: $connect")

		verifyConnection.close()

		return connect
	}
}