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

package dev.castive.javalin_auth.auth.provider.flow

import dev.castive.javalin_auth.api.OAuth2
import dev.castive.javalin_auth.auth.data.User2
import dev.castive.javalin_auth.auth.data.UserEntity
import io.javalin.core.security.BasicAuthCredentials

interface BasicAuthProvider<T> {
	val sourceName: String

	fun getAccessToken(basicAuth: BasicAuthCredentials, data: Any? = null): OAuth2.TokenResponse?

	fun refreshToken(token: String, data: Any? = null): OAuth2.TokenResponse?

	fun revokeToken(token: String, data: Any? = null)

	fun isTokenValid(token: String, data: Any? = null): Boolean

	fun getUserByName(username: String, data: Any? = null): User2?

	fun getUser(token: String, data: Any? = null): UserEntity<T>?
}