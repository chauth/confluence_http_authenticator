Confluence HTTP Authenticator
=====
(formerly Confluence Shibboleth Authenticator)

### Overview

Confluence HTTP Authenticator is an authenticator for Confluence that can be used with Shibboleth (tested with Shibboleth 1.3 and 2.0) and possibly other HTTP-authentication solutions.

Currently the authenticator takes the HTTP header that Shibboleth or something else passes into Confluence (usually REMOTE_USER) as the user's username (id) and either creates or updates a Confluence user in Confluence via Confluence API and can manage the groups memberships of that user based on Shibboleth (mace) attributes that have been configured to be passed into Confluence from Shibboleth. It relies on Shibboleth or something else to ensure that the header cannot be provided by the client itself, overriding the authentication mechanism.

Note: Those using Crowd (not just the embedded Crowd in Confluence) with Shibboleth may want to consider another solution.

(AS WITH PREVIOUS VERSIONS, THIS VERSION MUST BE MANUALLY INSTALLED AND CONFIG FILE ALTERED AND OTHER SETUP FOR SHIBBOLETH (OR SOMETHING ELSE) AND CONFLUENCE AS REQUIRED.)

This authenticator is also under its old name in the [Atlassian Marketplace][atlassianmarketplace]. (It was moved from Atlassian's Jira Studio when Atlassian decided to stop hosting community projects in 2013, and renamed as part of the move per discussion on the [Shibboleth Users mailing list][shibbolethuserlist].)

### Notes

For those upgrading to Confluence 4.3, be sure to shib guard the mobile login and logout path, e.g. the login path may be /plugins/servlet/mobile/login?originalUrl=%2Fplugins%2Fservlet%2Fmobile%23dashboard%2Fpopular. Note that these may be different depending on your version of Confluence.
* v2.1.16 released with compatibility enhancements.
* Confluence authenticator plugins cannot be installed via the Plugins/Plugin Repository admin UI in Confluence per Atlassian. You must put the jar in the classpath instead. Read all comments in CONF-22266 for details.
* Also download remoteUserAuthenticator.properties (see link next to appropriate release below) which is required along with the jar.
* Thoroughly read through all available documentation. If you have problems, please refer to the support section below in this document.

### Installation

* This plugin does not support installation via Plugin Repository/Plugins in Confluence. You may get the error, "The downloaded file is missing an atlassian-plugin.xml" if you try to install it from Plugin Repository in Confluence. Instead please follow the instructions in this document to get setup.
* Copy the jar file above into Confluence's WEB-INF/lib directory (and backup existing file). Be sure to note that versions of Confluence prior to 3.5.x require the older 1.x version of the plugin, and that Confluence 3.5.0-3.5.2 require the patch in CONF-22157 to Confluence.
* Copy the sample config file above into Confluence's WEB-INF/classes directory (and backup existing file).
* Read the pages linked in the Configuration section, as well as the rest of this page which provides important information on troubleshooting, support, and security. This plugin requires that the Shibboleth SP, Apache, Tomcat, and plugin are setup and configured correctly. If you have an alternate method for setting up or could help us by updating the documentation, please do! We appreciate your help.

Why isn't there support for installation of the plugin via Plugin Repository?

* Shibbolizing Confluence is just not as easy as installing a plugin currently. It requires the Shibboleth SP to be setup, Tomcat/etc. to be setup correctly to allow the REMOTE_USER header to be passed in from the SP, etc. If you were to install the plugin with everything else not set up, it might put Confluence into an unusable state until you determined how to manually remove the plugin.
* We would need to spend time developing an administrative configuration UI. There could be benefit to an administrative configuration UI for some configuration items, although it could still be dangerous to use them.

### Configuration

* See How to Shibbolize Confluence to get setup.
* See How to Configure Shibboleth Authenticator for Confluence for info on how to tweak the authenticator's config to take advantage of its many features.
* Be sure to read the read of this document for additional information about security and troubleshooting.

### How to Allow Anonymous Access to Certain Parts of Confluence

(The following information was provided by Vladimir Mencl.)

If you are running into issues where anyone accessing the space (or the whole Confluence server) is being forced to log in, you have to:

1. Give the Anonymous user the "Use Confluence" privilege at the Global level.

2. Give the Anonymous user the "View this space" privilege at the Space level.

3. Configure Shibboleth for Lazy sessions in mod_shib:

        module configuration ("ShibRequestSetting requireSession 0")

### Upgrading

* See release notes below for details.
* If upgrading any Confluence Shibboleth Authenticator version before v1.3 to v1.3+, please make sure to update your seraph config to use the new package name, so that the authenticator class is "shibauth.confluence.authentication.shibboleth.RemoteUserAuthenticator". For versions prior to plugin v1.3, continue to use "edu.georgetown.middleware.confluence.RemoteUserAuthenticator".

### Support

* This plugin is supported by those that use it (the best kind of support!). It is not supported by Atlassian yet.
* First read through this page (especially the Configuration, Troubleshooting, and Comments sections).
* Ensure Shibboleth is setup correctly by using the Shibboleth online documentation and Shibboleth users mailing list.
* Ensure Tomcat, Apache, etc. (whatever else you are using besides Shibboleth and whatever is serving or containing Confluence) is setup correctly and is working with Shibboleth using a combination of the Shibboleth support and available documentation and support for the web server and container.
* Assuming the issue you are having is not covered elsewhere, please go to http://studio.plugins.atlassian.com/browse/SHBL and search for your issue.
* If you find your issue, vote for it, watch it, and add a comment to the ticket to let us know you're having the issue also.
* If you can't find an existing ticket, please create one. Be sure to include your version of Confluence and other relevant information about your environment. It helps us if you can attach debug logs (see "How to Turn on Debug Logging" section below).

### Security

If combining Shibboleth authentication with local authentication, please be aware that, if Confluence is using self-registration, user A could register as a username via local authN if that username doesn't exist yet, and then user B could later authenticate as that same username via the Confluence Shibboleth Authenticator. Please be very careful and understand how the plugin works before considering combining it with local or any other authN methods. (Thanks to Matt Boesch for contributing this information that he, David Lotts, and Rajeev Gupta determined together in a testing environment.)

### Troubleshooting

Those with Shibboleth configuration issues should use the [Shibboleth Users mailing list][shibbolethuserlist] and those with Confluence issues should use the appropriate method to get support.

If you have an issue with the authenticator itself, please review the [issues][issues] and then create a new issue if there is no existing issue. The authenticator support is provided on a volunteer basis.

More help:

* v2.1.x of this plugin works with Confluence 4.1.x.
* v2.0.x of this plugin only works with Confluence 3.5.x-4.0.x. For Confluence 3.5.0-3.5.2, you must also install the Confluence patch attached to CONF-22157.
* v1.7.4 of this plugin (or later version of v1.x before v2.0) is required for Confluence 3.4.x and below.
* If you get the error "The downloaded file is missing an atlassian-plugin.xml", it is because you are trying to install the plugin jar using the Confluence Plugin Repository administrative UI. See Installation section for additional information.
* If you are getting the debug log message "Remote user was null or empty, can not perform authentication", this just means that the REMOTE_USER header is not being populated, which is not an issue with this plugin. As a quick check, if using Tomcat, in the AJP Coyote connector configuration part of server.xml, make sure you add tomcatAuthentication="false" or the REMOTE_USER header will not be communicated from Apache mod_jk to the AJP connector (as described in How to Shibbolize Confluence). However, please use the shibboleth-users@internet2.edu group to get support for that issue.
* If you're having any trouble configuring Shibboleth or Apache/Tomcat with Shibboleth in-general, please first pose your question(s) on the shibboleth users mailing list.
* Logout may not work properly. A workaround is to alter the logout page to indicate that the user must completely close the browser application to logout. Editing the logout page messages can be done in the ConfluenceActionSupport.properties file (/confluence/WEB-INF/classes/com/atlassian/confluence/core/ConfluenceActionSupport.properties). ConfluenceActionSupport.properties has the following message properties for the logout page: title.logout, com.atlassian.confluence.user.actions.LogoutAction.action.name, successful.logout.message, and logout.login.again. A search on any of those should bring you to the right spot. While not recommended, you're also able to edit the logout.vm file (/confluence/logout.vm) directly. Additionally, you will likely need to update any language packs you've installed (and in Confluence 2.6.0+, ConfluenceActionSupport.properties is embedded within one of the jars in Confluence, so you may need to extract it to find the properties you need to update and then just create a ConfluenceActionSupport.properties that overrides those properties or create a new language pack where those properties are changed).
* There may be an issue in v1.0 using the current authenticator with Confluence massive running with more than one node (CONF-9040) in which there is a unique constraint exception being thrown from Hibernate/Oracle when the user gets autocreated. The reason may be that the authenticator is being called at the same time by both nodes in when userManager.getUser() for the thread on server1 returns null and the userManager.getUser() is called for the thread on server2 which also returns null. The way this could be coded around is to do a try catch around createUser() and ignore unique constraint errors, however it doesn't seem right that the authenticator is being called on both servers for a single login, so this was logged as a bug in confluence. Please click on the link above and vote on this issue if you are getting unique constraint exceptions from the authenticator when using massive.
* Migrating from os_user schema to atlassian-user schema (see How to Improve User Search Performance) will fail if you've used v1.0 of this authenticator to autocreate users, since it creates users with null passwords. Even though the Confluence API supports creating users with null passwords, there was a bug in earlier versions of Confluence that cause Confluence to fail migration of these users (CONF-9117). The two workarounds provided by Atlassian support are to arbitrarily set a password with those users that have null passwords prior to the migration (via SQL update) (this works, but it is a little scary since you are giving a password hash field an arbitrary value, and this value is migrated also to the users table in the schema) or upgrade to the latest version of Confluence that fixes this problem (2.5.8 and 2.6.x+).
* Versions v1.5-v1.6 did not support local Confluence authentication because of use of the ShibLoginFilter introduced in v1.5. This was fixed in v1.7. Please note the security issues that can result by using local authN and self-registration. See the Security section of this document.

### How to Turn on Debug Logging

It helps to have debug logging of the plugin itself if something is wrong, so you can do the following to turn on debug logging, and then you can send the part of the log with the issue in the ticket (or attach the log as a file if the section is more than several lines long). To turn on debug logging, you can edit your .../confluence/WEB-INF/classes/log4j.properties file, add the following line and restart Confluence. Then after a login copy the relevant part of the confluence log into the Jira ticket in our Jira project or just attach it as a file:

For building Shibboleth Authenticator for Confluence from trunk and for Shibboleth Authenticator for Confluence v1.3+, use:

      log4j.logger.shibauth.confluence.authentication.shibboleth=DEBUG, confluencelog

For Shibboleth Authenticator for Confluence v1.0, v1.1, and v1.2 use:

      log4j.logger.edu.georgetown.middleware.confluence=DEBUG, confluencelog

(Those are assuming that you have "log4j.appender.confluencelog=org.apache.log4j.ConsoleAppender" defined above it, otherwise basically do whatever you need to to enable debug logging for that package.)

### Contributing

To contribute, read [using pull requests][fork].

#### Support

Please feel free to assist others with the authenticator itself and its configuration in any [issue][issues] if you can. Those with Shibboleth configuration issues should use the [Shibboleth Users mailing list][shibbolethuserlist] and those with Confluence issues should use the appropriate method.

#### Building

Build assumes Java 6+, Maven 3+. Atlassian SDK does not need to be installed, as it is an authenticator jar loaded on
classpath, not a plugin, nor can it or should it be, even in Confluence 4.x+.

For larger changes, you'd want to create an [issue][issues] first to ask if it would be something that would be of interest to everyone.

Although there is a Google group that we have if needed to discuss development as a team:
http://groups.google.com/group/confluence-shibauth-dev
which has a mailing list for development discussion:
confluence-shibauth-dev@googlegroups.com
please keep conversation out of that group and mailing list if it can instead be discussed within an [issue][issues] in GitHub.

Releases can be found [here][releases].

To build, type:

    mvn clean install

When committing, please try to include the issue number when possible in the beginning on the comment, e.g.:

    svn commit -m "#123 Added compatibility for Confluence v2.5"

#### Releasing a New Version

To release a new version:

1) Add yourself to the list of developers in the pom.xml.

2) Build and manually test jar in target/*.jar (or have someone test)

      mvn clean install

3) Edit pom.xml to be new release version (remove "-SNAPSHOT" from release version, e.g. change from 1.2.3-SNAPSHOT to 1.2.3)

4) Build and manually test again as needed (or have someone test)

      mvn clean install

5) Put changes from git log into release info in the CHANGELOG.md (note: prior releases used Jira ticket id, but newer releases should use the #(GitHub issue num) format, e.g. "#123 Added compatibility for Confluence v2.5").

6) Copy new release to releases directory, add pom.xml change and new release, commit, and push, then tag, and push tags:

      cp target/(name of jar).jar releases/
      git add releases
      git add pom.xml
      git commit -m "releasing 1.2.3"
      git push
      git tag v1.2.3
      git push --tags

7) Edit pom.xml to increment patch version and add "-SNAPSHOT" to version (e.g. change from 1.2.3 to 1.2.4-SNAPSHOT).

8) Add pom.xml, commit, and push.

      git add pom.xml
      git commit -m "incrementing pom.xml version to 1.2.4-SNAPSHOT"

9) Add release info/jar also to (this url may change):

      https://plugins.atlassian.com/plugins/shibauth.confluence.authentication.shibboleth

10) Have fun!

Troubleshooting:

Be sure to build with Java 6.

### Release Notes

See git log or the [CHANGELOG][changelog].

### License

Copyright (c) 2007-2013, Confluence HTTP Authenticator Team, released under a [BSD-style License][lic].

[changelog]: http://github.com/chauth/confluence_http_authenticator/blob/master/CHANGELOG.md
[atlassianmarketplace]: https://marketplace.atlassian.com/plugins/shibauth.confluence.authentication.shibboleth
[shibbolethuserlist]: http://shibboleth.net/community/lists.html
[fork]: https://help.github.com/articles/using-pull-requests
[releases]: https://github.com/chauth/confluence_http_authenticator/releases 
[issues]: https://github.com/chauth/confluence_http_authenticator/issues
[lic]: http://github.com/chauth/confluence_http_authenticator/blob/master/LICENSE