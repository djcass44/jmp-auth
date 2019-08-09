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

package dev.castive.javalin_auth.auth

import io.javalin.core.security.Role
import io.javalin.core.security.SecurityUtil

object Roles {
	enum class BasicRoles: Role {
		USER, ADMIN, ANYONE
	}
	val openAccessRole = SecurityUtil.roles(
		BasicRoles.ANYONE,
		BasicRoles.USER,
		BasicRoles.ADMIN
	)
	val defaultAccessRole = SecurityUtil.roles(
		BasicRoles.USER,
		BasicRoles.ADMIN
	)
	val adminAccessRole = SecurityUtil.roles(BasicRoles.ADMIN)
}