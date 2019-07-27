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
import dev.castive.log2.Log
import io.javalin.http.Context

object UserAction {
    var verification: UserVerification? = null

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