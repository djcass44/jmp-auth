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

import dev.castive.javalin_auth.auth.data.Group
import dev.castive.javalin_auth.auth.data.User

public interface BaseProvider {
    public fun setup()
    public fun tearDown()
    public fun getUsers(): ArrayList<User>?
    public fun getGroups(): ArrayList<Group>
    fun userInGroup(group: Group, user: User): Boolean
    public fun getLogin(uid: String, password: String): String?
    public fun getName(): String
    public fun connected(): Boolean
}