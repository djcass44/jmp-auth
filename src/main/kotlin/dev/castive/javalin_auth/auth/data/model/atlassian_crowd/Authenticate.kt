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

import com.google.gson.annotations.SerializedName

data class AuthenticateRequest(val username: String,
                               val password: String,
                               @SerializedName("validation-factors")
                               val validationFactors: ArrayList<Factor>? = null) {
}

data class AuthenticateResponse(val expand: String,
                                val token: String,
                                val user: User,
                                val link: Link,
                                @SerializedName("created-date")
                                val createdDate: Long,
                                @SerializedName("expiry-date")
                                val expiryDate: Long)

data class User(val name: String)
data class Link(val href: String, val rel: String)

data class BasicAuthentication(val username: String, val password: String)