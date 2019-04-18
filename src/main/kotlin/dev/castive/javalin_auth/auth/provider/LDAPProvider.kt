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

import dev.castive.javalin_auth.auth.connect.LDAPConfig
import dev.castive.javalin_auth.auth.connect.LDAPConnection
import dev.castive.javalin_auth.auth.data.Group
import dev.castive.javalin_auth.auth.data.User
import dev.castive.javalin_auth.auth.external.UserVerification
import dev.castive.log2.Log
import java.util.*
import javax.naming.AuthenticationException
import javax.naming.NamingException

public class LDAPProvider(private val config: LDAPConfig,
                   private val configExtras: LDAPConfig.Extras,
                   private val verification: UserVerification?): BaseProvider {
    public companion object {
        public const val SOURCE_NAME = "ldap"
    }
    private lateinit var connection: LDAPConnection

    var connected = false
        private set

    public override fun setup() = try {
        connection = LDAPConnection(config)
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

    public override fun tearDown() {
        connection.close()
    }

    public override fun getUsers(): ArrayList<User>? {
        val users = arrayListOf<User>()
        val result = connection.searchFilter(configExtras.userFilter) ?: return null
        for (r in result) {
            val username = r.attributes.get(configExtras.uid).get(0).toString()
            val role = r.attributes.get("objectClass").get(0).toString()
            users.add(User(username, role, SOURCE_NAME))
        }
        return users
    }
    public override fun getGroups(): ArrayList<Group> {
        throw NotImplementedError()
    }

    public override fun getLogin(uid: String, password: String): String? {
        val valid = connection.checkUserAuth(uid, password, configExtras.uid)
        return if (valid) verification?.getToken(uid)
        else null
    }

    public override fun getName(): String {
        return SOURCE_NAME
    }

    public override fun connected(): Boolean {
        return connection.connected
    }
}