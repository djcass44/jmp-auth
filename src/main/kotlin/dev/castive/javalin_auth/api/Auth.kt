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

package dev.castive.javalin_auth.api

import dev.castive.javalin_auth.auth.RequestUserLocator
import dev.castive.javalin_auth.auth.Roles
import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.Factor
import dev.castive.javalin_auth.auth.data.model.atlassian_crowd.ValidationFactors
import dev.castive.javalin_auth.auth.external.Session
import dev.castive.javalin_auth.auth.provider.Crowd2Provider
import dev.castive.javalin_auth.auth.provider.Internal2Provider
import dev.castive.javalin_auth.auth.provider.LDAP2Provider
import dev.castive.javalin_auth.auth.provider.flow.BasicAuthProvider
import dev.castive.javalin_auth.auth.response.Responses
import dev.castive.javalin_auth.config.Crowd2Config
import dev.castive.javalin_auth.config.LDAP2Config
import dev.castive.javalin_auth.util.ok
import dev.castive.log2.logd
import dev.castive.log2.logi
import dev.dcas.util.extend.json
import io.javalin.apibuilder.ApiBuilder.get
import io.javalin.apibuilder.ApiBuilder.post
import io.javalin.apibuilder.EndpointGroup
import io.javalin.core.security.BasicAuthCredentials
import io.javalin.http.BadRequestResponse
import io.javalin.http.NotFoundResponse
import io.javalin.http.UnauthorizedResponse
import javax.servlet.http.Cookie

class Auth<T : Any>(
	private val baseUrl: String,
	locator: RequestUserLocator.UserLocation<T>,
	session: Session<T>,
	ldapConfig: LDAP2Config,
	crowdConfig: Crowd2Config
): EndpointGroup {
	private val crowd = Crowd2Provider(locator, crowdConfig)

	private val providers = listOf(crowd, LDAP2Provider(locator, session, ldapConfig), Internal2Provider(locator, session))


	override fun addEndpoints() {
		post("$baseUrl/a2/login", { ctx ->
			val basic = ctx.bodyAsClass(BasicAuthCredentials::class.java)
			var token: Pair<OAuth2.TokenResponse, BasicAuthProvider<*>>? = null
			// iterate over all providers until one finds the user
			for (p in providers) {
				val t = p.getAccessToken(basic, ValidationFactors(arrayListOf(Factor("remote_address", ctx.ip()))).json())
				if(t != null) {
					token = t to p
					break
				}
			}
			// if we couldn't find the user at all throw a 404
			if(token == null)
				throw NotFoundResponse(Responses.NOT_FOUND_USER)
			if(token.second.sourceName == crowd.sourceName) {
				"Setting Crowd cookie: ${crowd.cookieConfig?.name}".logd(javaClass)
				// set the Crowd cookie
				ctx.res.addCookie(createCrowdCookie(token.first.request))
			}
			ctx.ok().json(token.first)
		}, Roles.openAccessRole)
		get("$baseUrl/a2/refresh", { ctx ->
			val refresh = ctx.queryParam("refreshToken", String::class.java, "").get()
			val source = ctx.header("X-Auth-Source") ?: throw BadRequestResponse(Responses.NO_SOURCE_HEADER)
			var token: OAuth2.TokenResponse? = null
			for(p in providers) {
				// find the matching provider
				if(p.sourceName == source) {
					token = p.refreshToken(refresh)
					break
				}
			}
			// TODO is this the most appropriate response?
			if(token == null)
				throw UnauthorizedResponse("Unable to refresh token")
			ctx.ok().json(token!!)
		}, Roles.openAccessRole)
		post("$baseUrl/a2/logout", { ctx ->
			val token = ctx.queryParam("accessToken", String::class.java).get()
			when(ctx.header("X-Auth-Source") ?: throw BadRequestResponse(Responses.NO_SOURCE_HEADER)) {
				crowd.sourceName -> crowd.revokeToken(token)
			}
			crowd.cookieConfig?.let {
				"Removing crowd cookie: ${it.name}".logi(javaClass)
				ctx.removeCookie(it.name)
			}
		}, Roles.defaultAccessRole)
	}

	private fun createCrowdCookie(token: String): Cookie = Cookie(crowd.cookieConfig!!.name, token).apply {
		domain = crowd.cookieConfig.domain
		secure = crowd.cookieConfig.secure
		isHttpOnly = true
		maxAge = Integer.MAX_VALUE
		path = "/"
	}
}