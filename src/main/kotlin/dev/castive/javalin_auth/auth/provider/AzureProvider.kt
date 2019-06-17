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

package dev.castive.javalin_auth.auth.provider

import com.microsoft.graph.authentication.IAuthenticationProvider
import com.microsoft.graph.core.ClientException
import com.microsoft.graph.requests.extensions.GraphServiceClient
import dev.castive.javalin_auth.auth.data.Group
import dev.castive.javalin_auth.auth.data.User
import dev.castive.log2.Log

@Deprecated(message = "This provider isn't ready.", level = DeprecationLevel.HIDDEN)
class AzureProvider(authProvider: IAuthenticationProvider): BaseProvider {
	companion object {
		const val SOURCE_NAME = "azure"
	}

	private val graphClient = GraphServiceClient.builder()
		.authenticationProvider(authProvider)
		.buildClient()

	override fun setup() {

	}

	override fun tearDown() {

	}

	override fun getUsers(): ArrayList<User> {
		val users = arrayListOf<User>()
		var usersRequestBuilder = graphClient.users()
		var usersRequest = usersRequestBuilder.buildRequest().top(999)
		do {
			try {
				val usersCollection = usersRequest.get()
				for (user in usersCollection.currentPage) {
					users.add(User(user.userPrincipalName, user.onPremisesDistinguishedName, user.userType, SOURCE_NAME))
				}
				// Get the next page if it exists
				usersRequestBuilder = usersCollection.nextPage
				if(usersRequestBuilder == null) usersRequest = null
				else usersRequest = usersRequestBuilder.buildRequest()
			}
			catch (e: ClientException) {
				Log.d(javaClass, "Failed to read users: $e")
				usersRequest = null
			}
		} while (usersRequest != null)
		return users
	}

	override fun getGroups(): ArrayList<Group> {
		val groups = arrayListOf<Group>()
		var groupsRequestBuilder = graphClient.groups()
		var groupsRequest = groupsRequestBuilder.buildRequest().top(999)
		do {
			try {
				val groupsCollection = groupsRequest.get()
				for (group in groupsCollection.currentPage) {
					groups.add(Group(group.displayName, group.displayName, SOURCE_NAME))
				}
				// Get the next page if it exists
				groupsRequestBuilder = groupsCollection.nextPage
				if(groupsRequestBuilder == null) groupsRequest = null
				else groupsRequest = groupsRequestBuilder.buildRequest()
			}
			catch (e: ClientException) {
				Log.d(javaClass, "Failed to read groups: $e")
				groupsRequest = null
			}
		} while (groupsRequest != null)
		return groups
	}

	override fun userInGroup(group: Group, user: User): Boolean {
		TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
	}

	override fun getLogin(uid: String, password: String, data: Any?): String? {
		TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
	}

	override fun getName(): String {
		return SOURCE_NAME
	}

	override fun connected(): Boolean {
		return true
	}

	override fun validate(token: String, data: Any): String? = "OK"

	override fun getSSOConfig(): Any? = null

	override fun invalidateLogin(id: String) {}
}