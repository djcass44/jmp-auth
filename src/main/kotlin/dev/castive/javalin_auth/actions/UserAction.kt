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

package dev.castive.javalin_auth.actions

import dev.castive.javalin_auth.auth.JWT
import dev.castive.javalin_auth.auth.TokenProvider
import dev.castive.javalin_auth.auth.external.UserVerification
import dev.castive.javalin_auth.auth.external.ValidUserClaim
import dev.castive.javalin_auth.auth.response.AuthenticateResponse
import dev.castive.log2.Log
import io.javalin.Context
import io.javalin.ForbiddenResponse

object UserAction {
    var verification: UserVerification? = null

    fun get(ctx: Context, verification: UserVerification, lax: Boolean = false): ValidUserClaim {
        val jwt = JWT.map(ctx) ?: run {
            ctx.header(AuthenticateResponse.header, AuthenticateResponse.response)
            Log.i(javaClass, "Failed to parse JWT")
            throw ForbiddenResponse("Token verification failed")
        }
        Log.ok(javaClass, "JWT parse valid")
        return if(lax) TokenProvider.verifyLax(jwt, verification)!! else TokenProvider.verify(jwt, verification) ?: run {
            ctx.header(AuthenticateResponse.header, AuthenticateResponse.response)
            Log.i(javaClass, "Token verification failed")
            throw ForbiddenResponse("Token verification failed")
        }
    }
    fun get(ctx: Context, lax: Boolean = false): ValidUserClaim {
        if(verification == null) {
            Log.e(javaClass, "No UserVerification has been setup.")
            throw NullPointerException()
        }
        return get(ctx, verification!!, lax)
    }
    fun getOrNull(ctx: Context, verification: UserVerification, lax: Boolean = false): ValidUserClaim? {
        val jwt = JWT.map(ctx) ?: ""
        return if(jwt == "null" || jwt.isBlank()) null
        else if(lax) TokenProvider.verifyLax(jwt, verification) else TokenProvider.verify(jwt, verification)
    }
    fun getOrNull(ctx: Context, lax: Boolean = false): ValidUserClaim? {
        if(verification == null) {
            Log.e(javaClass, "No UserVerification has been setup.")
            throw NullPointerException()
        }
        return getOrNull(ctx, verification!!, lax)
    }
}