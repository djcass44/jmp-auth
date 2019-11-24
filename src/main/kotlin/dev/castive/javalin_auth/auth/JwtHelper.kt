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

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import dev.castive.javalin_auth.auth.data.UserEntity
import dev.castive.javalin_auth.util.SigningKey
import dev.castive.log2.loge
import dev.castive.log2.logi
import dev.castive.log2.logw
import java.util.*
import java.util.concurrent.TimeUnit

class JwtHelper(
	private val requestLimit: Long = TimeUnit.HOURS.toMillis(1),
	private val refreshLimit: Long = TimeUnit.HOURS.toMillis(8)
) {
	private var signer: Algorithm = Algorithm.HMAC256(SigningKey.key)

	private val claimId = "sub"

	init {
		"Using token limits: [request: $requestLimit, refresh: $refreshLimit]".logi(javaClass)
	}

	fun buildSigner(key: String) {
		signer = Algorithm.HMAC256(key)
	}

	fun createRequestToken(user: UserEntity<*>): String = createToken(user, requestLimit)
	fun createRefreshToken(user: UserEntity<*>): String = createToken(user, refreshLimit)

	private fun createToken(user: UserEntity<*>, delay: Long): String {
		val expiry = Date(System.currentTimeMillis() + delay)
		return JWT.create()
			.withIssuer(javaClass.name)
			.withClaim(claimId, user.id.toString())
			.withClaim("username", user.username)
			.withClaim("source", user.source)
			.withExpiresAt(expiry)
			.withIssuedAt(Date(System.currentTimeMillis()))
			.sign(signer)
	}

	fun verify(token: String, leeway: Long = 1): String? {
		val jwtVerifier = JWT.require(signer)
			.withIssuer(javaClass.name)
			.acceptLeeway(TimeUnit.HOURS.toMillis(leeway))
			.build()
		return try {
			val decodedJWT = jwtVerifier.verify(token)
			// check if token has expired
			if(decodedJWT.expiresAt.before(Date(System.currentTimeMillis()))) {
				"Token has expired".logw(javaClass)
				return null
			}
			decodedJWT.getClaim(claimId).asString()
		}
		catch (e: Exception) {
			"Failed to validate token: $e".loge(javaClass)
			null
		}
	}
}