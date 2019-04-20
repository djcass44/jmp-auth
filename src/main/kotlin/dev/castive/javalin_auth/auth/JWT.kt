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

import io.javalin.Context

class JWT {
    companion object {
        const val headerToken = "X-Auth-Token"
        const val headerUser = "X-Auth-User"

        private lateinit var instance: JWT

        fun get(): JWT {
            if(!this::instance.isInitialized) instance = JWT()
            return instance
        }
    }

    fun map(ctx: Context): String? {
        val authHeader = ctx.header("Authorization")
        if(authHeader.isNullOrBlank())
            return null
        return try {
            val bearer = authHeader.split(" ")[0]
            if(bearer != "Bearer")
                return null
            val jwt = authHeader.split(" ")[1]
            // Check that the contents of the token look like a JWT
            if(TokenProvider.get().mayBeToken(jwt)) jwt else null
        }
        catch (e: IndexOutOfBoundsException) {
            null
        }
    }
}