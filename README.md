Confluence HTTP Authenticator
=====

### Overview

Confluence HTTP Authenticator (formerly known as Confluence Shibboleth Authenticator) is an authenticator for Confluence that supports request header and attribute based authentication. It can be used with Shibboleth (tested with Shibboleth 1.3 and 2.0) and possibly other HTTP authentication solutions.

Currently the authenticator takes the HTTP header that Shibboleth or something else passes into Confluence (usually REMOTE_USER) as the user's username (id) and either creates or updates a Confluence user in Confluence via Confluence API and can manage the groups memberships of that user based on Shibboleth (mace) attributes that have been configured to be passed into Confluence from Shibboleth. It relies on Shibboleth or something else to ensure that the header cannot be provided by the client itself, overriding the authentication mechanism.

Note: Those using Crowd (not just the embedded Crowd in Confluence) with Shibboleth may want to consider another solution.

(AS WITH PREVIOUS VERSIONS, THIS VERSION MUST BE MANUALLY INSTALLED AND CONFIG FILE ALTERED AND OTHER SETUP FOR SHIBBOLETH (OR SOMETHING ELSE) AND CONFLUENCE AS REQUIRED.)

This authenticator is also under its old name in the [Atlassian Marketplace][atlassianmarketplace]. (It was moved from Atlassian's Jira Studio when Atlassian decided to stop hosting community projects in 2013, and renamed as part of the move per discussion on the [Shibboleth Users mailing list][shibbolethuserlist].)

### Be Secure!

There are many security concerns that you should be aware of when setting up and configuring your SSO, Confluence, and the authenticator. Here are just a few, since there are too many to list here, and it is outside of the scope of this document:

* Don't allow local logins unless you take steps to block the Confluence "Invite Users" feature from functioning using mod_rewrite or similar methods. The invite feature establishes a static URL "back door" into the system that allows for total control over an account name and password, which allows an attacker to impersonate an SSO-based user account.
* If you use HTTP headers to define the username, email address, and/or fullname of users, be aware that users may be able to inject HTTP headers. If you must user HTTP headers for these, ensure that something is removing those user-provided headers. But it would be better to set the strategy for each attribute to 1 (request.getAttribute only. See remoteUserAuthenticator.properties for more information.) in the authenticator config and making adjustments as needed to your SSO to support that, if at all possible, e.g.

```
header.remote_user.strategy=1
header.email.strategy=1
header.fullname.strategy=1
```

* Consider disabling local login and not allowing anonymous access.

### Release Notes

*
* v2.7.5 in dev
* v2.7.4[+] require Java 8 and at least Confluence 7.11.6, see issue #61, #62
* v2.7.3 should be compatible up to the latest version of 7.8.1, see also issue #57.
* v2.7.2-2.7.3 should be compatible with Confluence 6.0.7+, up to the latest version of 6.x
* v2.7.0-v.2.7.1 should be compatible with Confluence 5.9.1+, up to the latest version of 5.x.
* v2.6.x should be compatible with Confluence 5.8.4+, up to the latest version of 5.8.x.
* v2.4.x-2.5.x should be compatible with Confluence 5.3.x up to the latest version of 5.7.x.
* v2.2.x should be compatible with Confluence 5.0.x thanks to a patch by William Schneider. Due to an api change, v2.2.x is not backwards compatible with previous Confluence versions.
* For those upgrading to Confluence 4.3 and higher, be sure to shib guard the mobile login and logout path, e.g. the login path may be /plugins/servlet/mobile/login?originalUrl=%2Fplugins%2Fservlet%2Fmobile%23dashboard%2Fpopular. Note that these may be different depending on your version of Confluence.
* v2.1.16 is for Confluence 4.1 through the latest version of 4. If you have problems with local login, use v2.1.15.
* v2.0.x of this plugin only works with Confluence 3.5.x-4.0.x. For Confluence 3.5.0-3.5.2, you must also install the Confluence patch attached to [CONF-22157][conf22157].
* v1.7.4 of this plugin (or later version of v1.x before v2.0) is required for Confluence 3.4.x and below.

### Installation Notes

* This plugin does not support installation via Plugin Repository/Plugins in Confluence, and Confluence authenticator plugins in general cannot be installed via the Plugins/Plugin Repository admin UI in Confluence per Atlassian. You must put the jar in the classpath instead. Read all comments in [CONF-22266][conf22266] for details. You may get the error, "The downloaded file is missing an atlassian-plugin.xml" if you try to install it from Plugin Repository in Confluence. Instead please follow the instructions in this document to get setup.
* Also download remoteUserAuthenticator.properties (see link next to appropriate release below) which is required along with the jar.
* Thoroughly read through all available documentation. If you have problems, please refer to the support section below in this document.
* Copy the jar file above into Confluence's WEB-INF/lib directory (and backup existing file). Be sure to note that versions of Confluence prior to 3.5.x require the older 1.x version of the plugin, and that Confluence 3.5.0-3.5.2 require the patch in [CONF-22157][conf22157] to Confluence.
* Copy the sample config file above into Confluence's WEB-INF/classes directory (and backup existing file).
* Read the pages linked in the Configuration section, as well as the rest of this page which provides important information on troubleshooting, support, and security. This plugin requires that the Shibboleth SP, Apache, Tomcat, and plugin are setup and configured correctly. If you have an alternate method for setting up or could help us by updating the documentation, please do! We appreciate your help.

### Configuration

The following describes how to configure the authenticator.

If you are using this authenticator with the Shibboleth SSO, you may refer to [How to Shibbolize Confluence](README-HOW_TO_SHIBBOLIZE.md) although it is old and may be outdated.

The authenticator uses Atlassian's (Java-based) Confluence User API to make changes to users and their group memberships. This means that if Atlassian's Confluence API supports those actions, then the authenticator should also be able to support those actions. If you aren't sure, try it and see (in your test environment).

#### About Configuration

The authenticator's config file is `remoteUserAuthenticator.properties`. A sample one comes with the version of the authenticator that you are using is provided as a separate download along with the authenticator jar, but you may need to tweak it for your environment. Back up any existing version of `remoteUserAuthenticator.properties`, and download the one for your version, and put it into Confluence's `WEB-INF/classes` directory.

A description of each property available in the plugin and how it can be configured is in the `remoteUserAuthenticator.properties` file provided as an additional download alongside the authenticator jar. To download that file, use the Download Now link at the [Atlassian Marketplace][atlassianmarketplace]. Additionally, download the `remoteUserAuthenticator.properties` file [here](conf/remoteUserAuthenticator.properties).

#### Basic Configuration

Note: There should NOT be quotes in the values of `header.fullname` and `header.email` as there were in a previous version of `remoteUserAuthenticator.properties`, the `header.fullname` and `header.email` need to match the header names in `AAP.xml`, and the Attribute Rules for the header names in `AAP.xml` need to be uncommented.

These properties are not optional, except `header.fullname` and `header.email`, which are only optional in Shib Auth for Conf v1.5 and greater (SHBL-18). See the sample config for more information on each property. Note that the values of the headers provided by Shibboleth can be empty (which will populate the Confluence user with empty values for those headers). It is strongly suggested if you want Confluence to create users, to also let it update the info (on each login), and to specify headers which more often than not will provide fullname and email values for each user (since these are used by the application).

For this example, I made the `header.fullname` and `header.email` match the headers defined by default in `AAP.xml`:

    create.users=true
    update.info=true
    default.roles=confluence-users
    header.fullname=Shib-InetOrgPerson-displayName
    header.email=Shib-InetOrgPerson-mail
    header.remote_user=REMOTE_USER
    
Note that even if you supply `update.info=true`, it will not attempt to update read-only users (such as those from an LDAP repository). That way the authenticator can support having both read-only and read-write user repositories.

Warning: Be sure to uncomment `header.remote_user` in the configuration and to change it to `REMOTE_USER` if that is how you are passing the username in, which is the typical usage. This will be fixed in future versions.

#### Dynamic Roles

This optional feature allows the authenticator to automatically assign users to roles based on attribute values they have, list the attribute name in `header.dynamicroles.attributenames` and specify the roles each value should map to. To automatically remove the user from the role when the user no longer has the attribute value, list the role also in `purge.roles`.

    header.dynamicroles.attributenames=SHIB-EP-ENTITLEMENT, Shib-EP-UnscopedAffiliation
    header.dynamicroles.testing=test-users, qa-test-users
    header.dynamicroles.some\:urn\:organization.com\:role\:manage=confluence-administrators
    purge.roles=test-users,qa-test-users

You can also use regex to map dynamically.  For example, if you wanted to take all the attributes in a header called {{nameofheader}}, and create groups in Confluence in the format 'prefix\-{{content}}' (so a user with {{nameofheader}}={{content}} becomes a member of the group {{prefix-content}}) then this would work:

    header.dynamicroles.attributenames=nameofheader
    
    dynamicroles.header.nameofheader=nameofmap

    dynamicroles.mapper.nameofmap.match=(.*)
    dynamicroles.mapper.nameofmap.transform=prefix-$1

You can then replace {{nameofheader}} and {{nameofmap}} to create your own mappings, and customise the regex ('match') and output ('transform') to suit your needs.  Only the set part (within brackets) of the regex will be passed to the transform in {{$1}}.

Note: If you are having trouble mapping roles, try using Shibboleth on the same server to guard a script that can print out the HTTP Headers being passed in from the SP, like the following PhP script from David Eisinger:
    
    <? print_r(apache_request_headers()); ?>

Look at the HTTP headers. The header.dynamicroles.attributenames values need to match the HTTP Header names coming from the SP. If you're not seeing the headers you want, talk to your Shibboleth administrator or email the [Shibboleth Users mailing list][shibbolethuserlist] to get Shibboleth support (and first try turning on debug logging in Shibboleth to make sure the IdP is sending the SP what you think it should be).

#### Getting Usernames From Different LDAP Attributes in HTTP Header Using Regular Expressions

This optional feature may be applied almost immediately after reading the `REMOTE_USER` HTTP header before cleaning username (next section). By default the header is splitted by the characters "[,;]" * into a list. The default strategy

    username.filter.strategy=0
    
now fetches the first entry of the list and puts it into the username pipeline. On the other side the strategy
     username.filter.strategy=1 
     
allows the authenticator to skip this behaviour and investigate each entry in the list. The first entry, which has a non empty matching group, i.e. matches the regular expression defined in username.filter will be set to the username at this point. If nothing matches the fallback will be the default result.

  * not yet configurable defined in StringUtil.SEPARATOR.
 
#### Cleaner Usernames Using Regular Expressions

This optional feature allows the authenticator to generate the username based on a regular expression based on the `REMOTE_USER` header instead of just using the exact value of `REMOTE_USER` header.

    # Example: suppose the remote user has initial value
    #   "https://idp.edu/idp!https://sp.edu/shibboleth!1234-56789-#00%00-TTT"
    # and we would like it to be transformed to
    #   "123456789A00c00@idp.edu"
    # then we can define the following:
    remoteuser=remoteusermap
    remoteuser.replace=#,A,%,c,(-|TTT),,
    remoteuser.map.remoteusermap.match = ^(http|https)://(.*?)(:|/)?[^!]*?!([^!]*?)!(.*)
    remoteuser.map.remoteusermap.casesensitive = false
    remoteuser.map.remoteusermap.transform = $5@$2
    #
    # remoteusermap is the mapping label to be used, multiple labels
    # can be used but only 1st result from the label is chosen as remote user)
    #
    # .replace is pair-wise regex & replacement strings to be applied to the FINAL
    # remote-user once the mapping has been performed. null (as replacement string)
    # can be represented by simply empty string (e.g. '-' and 'TTT' above are removed)


#### Cleaner Full Names Using Regular Expressions

This optional feature allows the authenticator to do mapping on values presented in header defined as value of `header.fullname`. This is for those that don't have a "display name" type attribute that can be exposed to Confluence's Shibboleth SP, but must put a full name together from multiple values, etc. This feature has similar syntax to dynamic roles. If a regex map doesn't match the input provided, then the mapping is not performed, and it will use the first value of that header.

    # Example 1: suppose the full name has the header value
    #   "Doe; John"
    # and we would like it to be transformed to
    #   "John Doe"
    # then we can define the following:
    fullname=fullnamemap
    fullname.map.fullnamemap.match = ^(.*);(.*)
    fullname.map.fullnamemap.casesensitive = false
    fullname.map.fullnamemap.transform = $2 $1
    # Note: if the expression doesn't match, it will split the string by comma or semi-colon and get the first value, so
    # the fullname would be:
    #   "Doe"


    # Example 2: suppose the full name has the header value
    #   "Doe#,%John"
    # and we would like it to be transformed to
    #   "John Doe"
    # then we can define the following:
    fullname=fullnamemap
    fullname.replace=#,,%,,
    fullname.map.fullnamemap.match = ^(.*),(.*)
    fullname.map.fullnamemap.casesensitive = false
    fullname.map.fullnamemap.transform = $2 $1
    # Note: if the expression doesn't match, it will split the string by comma or semi-colon and get the first value, so
    # the fullname would be:
    #   "Doe#"
    #
    # fullnamemap is the mapping label to be used, multiple labels
    # can be used but only 1st result from the label is chosen as remote user)
    #
    # .replace is pair-wise regex & replacement strings to be applied to the FINAL
    # full name once the mapping has been performed. null (as replacement string)
    # can be represented by simply empty string (e.g. '-' and 'TTT' above are removed)

#### Automatically Reloading the Configuration File

Restarting Confluence after adding a dynamic mapping would have too much impact on a production environment.  To make the module check for changes to the configuration file (`remoteAuthentication.propeties`) on each user login and reloads the file if changed, set the `reload.config` property. It is also possible to set a minimal delay between the checks (in milliseconds, defaults to 0).

    reload.config=true
    reload.config.check.interval=5000

#### Character Set Conversion

To convert HTTP header values to UTF-8           :

    convert.to.utf8=true

#### Using a Read-only User Repository

If you are only using a read-only repository such as LDAP for users, then you may want to disable the options that attempt to update user information by doing this in the config:

    create.users=false
    update.info=false

However, you should just be able to still have create-users as true and update-info as true and it shouldn't try to create the user (since it exists) nor should it attempt to update existing users (because it checks to see whether the user is read-only).

Assuming you needed to add those read-only users to the confluence-users group, and the Confluence API has the ability to create those group memberships, the following default settings for those options should work:

    default.roles=confluence-users
    update.roles=true

#### Using ShibLoginFilter

The ShibLoginFilter was introduced in v1.5 and is turned off by default in v1.7 because it kept those wanting to use local authN from being able to do that while using the authenticator. To turn it back on you can set this to true, but it shouldn't be needed and you should see the problems with it discussed in SHBL-24 if you decide to do that. Use of the ShibLoginFilter is deprecated and it will likely be removed in a later release.

    # Set this to true if you'd like to use the ShibLoginFilter that was used in v1.5, v1.5.1, and v1.6 of the plugin,
    # which requires Confluence to be using shibauth.confluence.authentication.shibboleth.ShibLoginFilter which in some/most
    # versions of Confluence involves Confluence's web.xml to be altered such that it contains:
    # <filter-name>login</filter-name>
    # <filter-class>shibauth.confluence.authentication.shibboleth.ShibLoginFilter</filter-class>
    # See SHBL-24

    # OPTIONAL:
    using.shib.login.filter=true

Warning: If you are unsure, leave this commented out or set to false. If you set using.shib.login.filter to true, then local authN will not work. Use of the shib login filter is deprecated and off by default. This option was created and left here for compatibility with previous versions and will be removed completely in a future version.

### How to Allow Anonymous Access to Certain Parts of Confluence

(The following information was provided by Vladimir Mencl.)

If you are running into issues where anyone accessing the space (or the whole Confluence server) is being forced to log in, you have to:

1. Give the Anonymous user the "Use Confluence" privilege at the Global level.

2. Give the Anonymous user the "View this space" privilege at the Space level.

3. Configure Shibboleth for Lazy sessions in mod_shib:

        module configuration ("ShibRequestSetting requireSession 0")

### Upgrading

* See release notes below for details.
* If upgrading any Confluence HTTP Authenticator version before v1.3 to v1.3+, please make sure to update your seraph config to use the new package name, so that the authenticator class is "shibauth.confluence.authentication.shibboleth.RemoteUserAuthenticator". For versions prior to plugin v1.3, continue to use "edu.georgetown.middleware.confluence.RemoteUserAuthenticator".

### Support

* This plugin is supported by those that use it (the best kind of support!). It is not supported by Atlassian yet.
* First read through this page (especially the Configuration, Troubleshooting, and Comments sections).
* Ensure Shibboleth is setup correctly by using the Shibboleth online documentation and Shibboleth users mailing list.
* Ensure Tomcat, Apache, etc. (whatever else you are using besides Shibboleth and whatever is serving or containing Confluence) is setup correctly and is working with Shibboleth using a combination of the Shibboleth support and available documentation and support for the web server and container.
* Assuming the issue you are having is not covered elsewhere, please go to the [issue tracker][issues] and search for your issue.
* If you find your issue, watch it and add a comment to the ticket to let us know you're having the issue also.
* If you can't find an existing ticket, please create one. Be sure to include your version of Confluence and other relevant information about your environment. It helps us if you can attach debug logs (see "How to Turn on Debug Logging" section below).

### Security

If combining Shibboleth authentication with local authentication, please be aware that, if Confluence is using self-registration, user A could register as a username via local authN if that username doesn't exist yet, and then user B could later authenticate as that same username via the Confluence HTTP Authenticator. Please be very careful and understand how the plugin works before considering combining it with local or any other authN methods. (Thanks to Matt Boesch for contributing this information that he, David Lotts, and Rajeev Gupta determined together in a testing environment.)

### Troubleshooting

Those with Shibboleth configuration issues should use the [Shibboleth Users mailing list][shibbolethuserlist] and those with Confluence issues should use the appropriate method to get support.

If you have an issue with the authenticator itself, please review the [issues][issues] and then create a new issue if there is no existing issue. The authenticator support is provided on a volunteer basis.

Feel free to contact someone on the team directly if you want to contribute anonymously, submit a security concern, or generallt want to mention something that shouldn't be public.

*Needs cleanup: The following is partially out-of-date.*

* If you get the error "The downloaded file is missing an atlassian-plugin.xml", it is because you are trying to install the plugin jar using the Confluence Plugin Repository administrative UI. See Installation section for additional information.
* If you are getting the debug log message "Remote user was null or empty, can not perform authentication", this just means that the `REMOTE_USER` header is not being populated, which is not an issue with this plugin. As a quick check, if using Tomcat, in the AJP Coyote connector configuration part of `server.xml`, make sure you add `tomcatAuthentication="false"` or the `REMOTE_USER` header will not be communicated from Apache mod_jk to the AJP connector (as described in [How to Shibbolize Confluence](README-HOW_TO_SHIBBOLIZE.md) ). However, please use the shibboleth-users@internet2.edu group to get support for that issue.
* If you're having any trouble configuring Shibboleth or Apache/Tomcat with Shibboleth in-general, please first pose your question(s) on the shibboleth users mailing list.
* Logout may not work properly. A workaround is to alter the logout page to indicate that the user must completely close the browser application to logout. Editing the logout page messages can be done in the ConfluenceActionSupport.properties file (`/confluence/WEB-INF/classes/com/atlassian/confluence/core/ConfluenceActionSupport.properties`). ConfluenceActionSupport.properties has the following message properties for the logout page: `title.logout`, `com.atlassian.confluence.user.actions.LogoutAction.action.name`, `successful.logout.message`, and `logout.login.again`. A search on any of those should bring you to the right spot. While not recommended, you're also able to edit the `logout.vm` file (`/confluence/logout.vm`) directly. Additionally, you will likely need to update any language packs you've installed (and in Confluence 2.6.0+, `ConfluenceActionSupport.properties` is embedded within one of the jars in Confluence, so you may need to extract it to find the properties you need to update and then just create a ConfluenceActionSupport.properties that overrides those properties or create a new language pack where those properties are changed).
* There may be an issue in v1.0 using the current authenticator with Confluence massive running with more than one node ([CONF-9040][conf9040]) in which there is a unique constraint exception being thrown from Hibernate/Oracle when the user gets autocreated. The reason may be that the authenticator is being called at the same time by both nodes in when `userManager.getUser()` for the thread on server1 returns null and the `userManager.getUser()` is called for the thread on server2 which also returns null. The way this could be coded around is to do a try catch around `createUser()` and ignore unique constraint errors, however it doesn't seem right that the authenticator is being called on both servers for a single login, so this was logged as a bug in confluence. Please click on the link above and vote on this issue if you are getting unique constraint exceptions from the authenticator when using massive.
* Migrating from os_user schema to atlassian-user schema (see How to Improve User Search Performance) will fail if you've used v1.0 of this authenticator to autocreate users, since it creates users with null passwords. Even though the Confluence API supports creating users with null passwords, there was a bug in earlier versions of Confluence that cause Confluence to fail migration of these users ([CONF-9117][conf9117]). The two workarounds provided by Atlassian support are to arbitrarily set a password with those users that have null passwords prior to the migration (via SQL update) (this works, but it is a little scary since you are giving a password hash field an arbitrary value, and this value is migrated also to the users table in the schema) or upgrade to the latest version of Confluence that fixes this problem (2.5.8 and 2.6.x+).
* Versions v1.5-v1.6 did not support local Confluence authentication because of use of the `ShibLoginFilter` introduced in v1.5. This was fixed in v1.7. Please note the security issues that can result by using local authN and self-registration. See the Security section of this document.

### How to Turn on Debug Logging

It helps to have debug logging of the plugin itself if something is wrong, so you can do the following to turn on debug logging, and then you can send the part of the log with the issue in the ticket (or attach the log as a file if the section is more than several lines long). To turn on debug logging, you can edit your .../confluence/WEB-INF/classes/log4j.properties file, add the following line and restart Confluence. Then after a login copy the relevant part of the confluence log into the Jira ticket in our Jira project or just attach it as a file:

For building Confluence HTTP Authenticator from trunk and for Confluence HTTP Authenticator v1.3+, use:

      log4j.logger.shibauth.confluence.authentication.shibboleth=DEBUG, confluencelog

For Confluence HTTP Authenticator v1.0, v1.1, and v1.2 use:

      log4j.logger.edu.georgetown.middleware.confluence=DEBUG, confluencelog

(Those are assuming that you have `log4j.appender.confluencelog=org.apache.log4j.ConsoleAppender` defined above it, otherwise basically do whatever you need to to enable debug logging for that package.)

### Contributing

To contribute, read [using pull requests][fork]. Feel free to contact someone on the team directly if you want to contribute anonymously.

#### Support

Please feel free to assist others with the authenticator itself and its configuration in any [issue][issues] if you can. Those with Shibboleth configuration issues should use the [Shibboleth Users mailing list][shibbolethuserlist] and those with Confluence issues should use the appropriate method.

#### Building

Read [technical howto][technical].

Please discuss publically within an [issue][issues] in GitHub.

#### Releasing a New Version

To release a new version, read [technical howto][technical].

Releases can be found [here][releases].

Troubleshooting:

Check Java issues here:
  https://confluence.atlassian.com/doc/supported-platforms-207488198.html#SupportedPlatforms-Java

### Release Notes

See git log or the [CHANGELOG][changelog].

### License

Copyright (c) 2008-2019, Confluence HTTP Authenticator Team, released under a [BSD-style License][lic].

[changelog]: http://github.com/chauth/confluence_http_authenticator/blob/master/CHANGELOG.md
[atlassianmarketplace]: https://marketplace.atlassian.com/plugins/shibauth.confluence.authentication.shibboleth
[shibbolethuserlist]: http://shibboleth.net/community/lists.html
[fork]: https://help.github.com/articles/using-pull-requests
[releases]: https://github.com/chauth/confluence_http_authenticator/releases 
[issues]: https://github.com/chauth/confluence_http_authenticator/issues
[lic]: http://github.com/chauth/confluence_http_authenticator/blob/master/LICENSE
[conf22266]: https://jira.atlassian.com/browse/CONF-22266 "Seraph in Confluence 3.5 environment no longer able to instantiate custom authenticator"
[conf22157]: https://jira.atlassian.com/browse/CONF-22157 "Custom authenticators which subclass ConfluenceAuthenticator are broken in Confluence 3.5"
[conf9040]: https://jira.atlassian.com/browse/CONF-9040 "Authenticator (subclass of DefaultAuthenticator) can be called twice at almost exactly same time by 2 or more clustered servers"
[conf9117]: https://jira.atlassian.com/browse/CONF-9117 "Confluence API supports adding user with null password, but users will null passwords produce NullPointerException when using the osuser to atlassian-user migration utility jsp"
[technical]: https://github.com/chauth/confluence_http_authenticator/blob/master/TECHNICAL_HOW_TO.md
