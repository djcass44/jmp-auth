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

package dev.castive.javalin_auth.auth.data.model.atlassian_crowd

data class UserSearch(val expand: String, val users: Array<Users>) {
	override fun equals(other: Any?): Boolean {
		if (this === other) return true
		if (javaClass != other?.javaClass) return false

		other as UserSearch

		if (expand != other.expand) return false
		if (!users.contentEquals(other.users)) return false

		return true
	}

	override fun hashCode(): Int {
		var result = expand.hashCode()
		result = 31 * result + users.contentHashCode()
		return result
	}
}

data class Users(val link: Link, val name: String)