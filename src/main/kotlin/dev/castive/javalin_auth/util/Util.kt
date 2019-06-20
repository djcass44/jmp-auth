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

package dev.castive.javalin_auth.util

import com.google.gson.GsonBuilder
import org.apache.commons.codec.binary.Base64
import java.nio.charset.StandardCharsets

object Util {
	fun basicAuth(username: String, password: String) = "Basic ${Base64.encodeBase64URLSafeString("$username:$password".toByteArray(StandardCharsets.UTF_8))}"

	val gson = GsonBuilder().setPrettyPrinting().create()!!
}