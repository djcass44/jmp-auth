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

import com.auth0.jwt.algorithms.Algorithm
import dev.castive.javalin_auth.auth.external.UserVerification
import dev.castive.javalin_auth.auth.external.ValidUserClaim
import dev.castive.log2.Log
import dev.castive.securepass3.PasswordGenerator
import java.util.*
import java.util.concurrent.TimeUnit

public class TokenProvider {
    class TokenAgeProfile(val tokenLimit: Long = TimeUnit.HOURS.toMillis(1), val refreshLimit: Long = TimeUnit.HOURS.toMillis(8)) {
        companion object {
            val DEFAULT = TokenAgeProfile(TimeUnit.HOURS.toMillis(1), TimeUnit.HOURS.toMillis(8))
            val DEV = TokenAgeProfile(TimeUnit.MINUTES.toMillis(1), TimeUnit.MINUTES.toMillis(5))
        }
    }

    public companion object {
        private lateinit var instance: TokenProvider

        public fun get(): TokenProvider {
            if(!this::instance.isInitialized) instance = TokenProvider()
            return instance
        }

        var ageProfile = TokenAgeProfile.DEFAULT
    }

    private val algorithm: Algorithm = Algorithm.HMAC256(PasswordGenerator().generate(32, false).toString()) // Strong causes blocking issues in Docker

    // This should only be used for request tokens
    public fun create(user: String): String? = try {
        val expiry = Date(System.currentTimeMillis() + ageProfile.refreshLimit)
        com.auth0.jwt.JWT.create()
            .withIssuer(javaClass.name)
            .withClaim(JWT.headerUser, user)
            .withClaim(JWT.headerToken, UUID.randomUUID().toString())
            .withExpiresAt(expiry)
            .withIssuedAt(Date(System.currentTimeMillis()))
            .sign(algorithm)
    }
    catch (e: Exception) {
        Log.e(javaClass, "Failed to generate token: [user: $user, cause: $e]")
        null
    }
    public fun create(user: String, userToken: String): String? = try {
        // Expires in 1 hour
        val expiry = Date(System.currentTimeMillis() + ageProfile.tokenLimit)
        com.auth0.jwt.JWT.create()
            .withIssuer(javaClass.name)
            .withClaim(JWT.headerUser, user)
            .withClaim(JWT.headerToken, userToken)
            .withExpiresAt(expiry)
            .withIssuedAt(Date(System.currentTimeMillis()))
            .sign(algorithm)
    }
    catch (e: Exception) {
        Log.e(javaClass, "Failed to generate token: [user: $user, cause: $e]")
        null
    }
    public fun verifyLax(token: String, verification: UserVerification): ValidUserClaim? {
        val verify = com.auth0.jwt.JWT.require(algorithm)
            .withIssuer(javaClass.name)
            .acceptLeeway(TimeUnit.HOURS.toMillis(1))
            .build()
        return try {
            val result = verify.verify(token)
            // Verify the user outside of this module
            val userHeader = result.getClaim(JWT.headerUser).asString()
            val tokenHeader = result.getClaim(JWT.headerToken).asString()
            val v = verification.verify(userHeader, tokenHeader)
            return if (v) ValidUserClaim(userHeader, tokenHeader) else null
        }
        catch (e: Exception) {
            Log.e(javaClass, "Failed lax token verification: $e")
            null
        }
    }
    public fun verify(token: String, verification: UserVerification): ValidUserClaim? {
        val verify = com.auth0.jwt.JWT.require(algorithm)
            .withIssuer(javaClass.name)
            .acceptLeeway(TimeUnit.HOURS.toMillis(1))
            .build()
        return try {
            val result = verify.verify(token)
            if(result.expiresAt.before(Date(System.currentTimeMillis()))) // Token has expired
                return null
            // Verify the user outside of this module
            val userHeader = result.getClaim(JWT.headerUser).asString()
            val tokenHeader = result.getClaim(JWT.headerToken).asString()
            val v = verification.verify(userHeader, tokenHeader)
            return if (v) ValidUserClaim(userHeader, tokenHeader) else null
        }
        catch (e: Exception) {
            Log.e(javaClass, "Failed token verification: $e")
//            e.printStackTrace()
            null
        }
    }
    public fun mayBeToken(token: String?): Boolean {
        return (token != null && token.isNotBlank() && token != "null" && token.split(".").size == 3)
    }
}