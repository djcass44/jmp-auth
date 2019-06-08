package dev.castive.javalin_auth.auth.data.model.atlassian_crowd

data class CrowdCookieConfig(val domain: String, val secure: Boolean, val name: String)
data class CrowdCookie(val host: String, val domain: String = "TRUE", val secure: Boolean, val expire: String = "", val name: String = "crowd.token_key", val token: String)