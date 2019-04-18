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

package dev.castive.javalin_auth.auth

import dev.castive.javalin_auth.auth.connect.LDAPConfig
import dev.castive.javalin_auth.auth.external.UserIngress
import dev.castive.javalin_auth.auth.external.UserVerification
import dev.castive.javalin_auth.auth.provider.BaseProvider
import dev.castive.javalin_auth.auth.provider.InternalProvider
import dev.castive.javalin_auth.auth.provider.LDAPProvider
import dev.castive.log2.Log
import java.util.*
import kotlin.concurrent.fixedRateTimer

class Providers(private val ldapConfig: LDAPConfig, private val ldapConfigExtras: LDAPConfig.Extras) {
    companion object {
        lateinit var internalProvider: InternalProvider
        var primaryProvider: BaseProvider? = null

        lateinit var validator: UserIngress
        lateinit var verification: UserVerification
    }

    private var syncAttempts = 0
    private lateinit var syncTimer: Timer

    fun init(verification: UserVerification) {
        Providers.verification = verification
        internalProvider = InternalProvider(verification)
        initLDAP()
    }

    /**
     * Try to setup LDAP provider if it's enabled
     */
    private fun initLDAP() {
        primaryProvider = LDAPProvider(ldapConfig, ldapConfigExtras, verification)

        startCRON()
    }

    private fun startCRON() {
        syncTimer = fixedRateTimer(javaClass.name, true, 0, ldapConfigExtras.syncRate) { sync() }
    }

    private fun sync() {
        val maxAttempts = ldapConfigExtras.maxConnectAttempts
        if(syncAttempts >= maxAttempts) { // Give up if we fail more than 5 times (default 25 minutes)
            Log.f(javaClass, "Reached maximum failure rate for LDAP sync, giving up")
            syncTimer.cancel()
            return
        }
        syncAttempts++
        if(primaryProvider == null) {
            Log.i(javaClass, "Skipping user sync, no provider setup")
            return
        }
        Log.i(javaClass, "Running batch update using ${primaryProvider!!::class.java.name}")
        Log.v(javaClass, "${primaryProvider!!::class.java.name} attempt $syncAttempts/$maxAttempts")
        primaryProvider!!.setup()
        val users = primaryProvider!!.getUsers()
        if(users == null) {
            Log.w(javaClass, "External provider: ${primaryProvider?.getName()} returned null, perhaps it's not connected yet?")
            return
        }
        Log.i(javaClass, "External provider: ${primaryProvider?.getName()} found ${users.size} users")
        syncAttempts = 0 // Reset counter because we got a valid connection
        validator.ingestUsers(users)
    }
}