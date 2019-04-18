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
import dev.castive.javalin_auth.auth.external.UserVerification

public class InternalProvider(private val verification: UserVerification?): BaseProvider {
    public companion object {
        public const val SOURCE_NAME = "local"
    }

    public override fun setup() {

    }

    public override fun tearDown() {

    }

    public override fun getUsers(): ArrayList<User>? {
        return arrayListOf()
    }

    public override fun getGroups(): ArrayList<Group> {
        return arrayListOf()
    }

    public override fun getLogin(uid: String, password: String): String? {
        return verification?.getToken(uid, password)
    }

    public override fun getName(): String {
        return SOURCE_NAME
    }

    public override fun connected(): Boolean {
        return true
    }
}