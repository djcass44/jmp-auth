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

internal object EnvUtil {
	fun getEnv(name: String, default: String = ""): String {
		val env = System.getenv(name)
		return if (env.isNullOrEmpty()) default else env
	}

	const val GITHUB_ENABLED = "GITHUB_ENABLED"
	const val GITHUB_CALLBACK = "GITHUB_CALLBACK"
	const val GITHUB_CLIENT_ID = "GITHUB_CLIENT_ID"
	const val GITHUB_CLIENT_SECRET = "GITHUB_CLIENT_SECRET"

	const val GOOGLE_ENABLED = "GOOGLE_ENABLED"
	const val GOOGLE_CALLBACK = "GOOGLE_CALLBACK"
	const val GOOGLE_CLIENT_ID = "GOOGLE_CLIENT_ID"
	const val GOOGLE_CLIENT_SECRET = "GOOGLE_CLIENT_SECRET"
}