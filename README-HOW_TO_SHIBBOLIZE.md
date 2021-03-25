**Note:** Part of this information and related documentation was formerly located at https://wiki.shibboleth.net/confluence/display/SHIB/ShibbolizedConfluence and was primarily written by Scott Cantor (Ohio State University) for Internet2, with additional information from Will Norris (University of Southern California), Gary Weaver (Duke University), and Renald Provey (Duke University).


I'm going to gloss over most of the actual Confluence configuration steps. Given a site running the product, we were able to take these steps to federate it and replace the local authentication mechanism with Shibboleth.


First, establish where the Confluence site lives in the document tree. In our case, we moved it to the root of the web server, but some of the configuration options will depend on where the root of your Wiki is. In particular, any references to {{/Shibboleth.sso}} will need to be prefixed with any subfolders that form the root of the Confluence site. Anywhere you see "wiki.example.edu", just replace with your hostname.

Another variant of this documentation is here: https://wiki.umbc.edu/display/MW/Shibboleth-enabling+Confluence


#### Before You Start

* Please read [Confluence Shibboleth Authenticator](README.md).
* Make sure that you have at least one user created in confluence with admin rights and with the same username as the username that will come into the authenticator from Shibboleth per your authenticator configuration. Otherwise, it will be painful to shibbolize, login, realize you don't have any admins, and have to unshibbolize just to give admin rights to the newly created user(s). When you create users, all that is important is that the username matches the username that will come into the authenticator from Shibboleth per your authenticator configuration. Password, etc. are not important, however you may want to use something unique and hard to guess for the password for security reasons (in case the app gets accidentally unshibbolized and exposed during an upgrade).

#### Confluence Setup

* There's an Admin setting for "Server Base Url" that needs to be configured properly. Various redirects through Shibboleth will depend on that value being correctly set to the root of the Wiki site.
* Download the jar from the Download JAR link in the top section of [Confluence Shibboleth Authenticator](README.md) and the remoteUserAuthenticator.properties file in the link in the comment below the jar link. This Seraph login plugin enables attribute-based authentication to the system. The code was originally written by Chad La Joie while at Georgetown and is now hosted by Atlassian (but not supported by them) and continues to be developed by the open-source community. The plugin includes options you can set in the {{conf/remoteUserAuthenticator.properties}} file.
* Install the plugin by copying it (remoteUserAuth-xxx.jar) into the Confluence webapp's {{WEB-INF/lib}} folder.
* Copy remoteUserAuthenticator.properties into the Confluence webapp's {{WEB-INF/classes}} folder.
* See [How to Configure Shibboleth Authenticator for Confluence] for info on configuring remoteUserAuthenticator.properties.
* Configure the Seraph layer to use the plugin by modifying {{WEB-INF/classes/seraph-config.xml}}:
  * Replace the {{authenticator}} element's {{class}} attribute with one of these values depending on the version of the plugin you are using (note: this should be the package name and class name of your class if you have made such customizations):
     * _For plugin version v1.0-1.2 use_: "edu.georgetown.middleware.confluence.RemoteUserAuthenticator"
     * _For plugin version v1.3\+ use_: "shibauth.confluence.authentication.shibboleth.RemoteUserAuthenticator
   Instead of replacing you might want to add a new authenticator keeping the the original authenticator "com.atlassian.confluence.user.ConfluenceAuthenticator" commented.
  * In the {{init-params}} element, set both the {{login.url}} and {{link.login.url}} parameter values to one of these:
     * if your wiki is only accessible via https:

                "/Shibboleth.sso/Login?target=https%3A%2F%2Fwiki.example.edu${originalurl}"

     * if your wiki is accessible via http but the Shibboleth.sso module is available via https:

                "https://wiki.example.edu/Shibboleth.sso/Login?target=${originalurl}"
                
     * The suffix */Login* in the above settings corresponds to the location of the [SessionInitiator](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPSessionInitiator) within the SP, and may be some other value, particularly in older SP versions. Beginning with V2.4, the SP defaults this to */Login* via the [SSO](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPServiceSSO) element.

#### Apache, Tomcat, Shibboleth, etc. Setup

We want to help you get completely set up, because it isn't simple. However, for anything (including Apache, Tomcat, Shibboleth, etc.) other than setting up Confluence for the authenticator, and the authenticator itself, you need to:
* Review the [Shibboleth documentation](https://wiki.shibboleth.net/confluence/display/SHIB2/) for basic information on setting up an SP and configuring support for the attributes you want to accept and pass along to Confluence.
* Pose any SP-related questions to the [Shibboleth users mailing list](http://shibboleth.internet2.edu/lists.html).

The basic requirements are:
* configure the SP to protect the entire confluence web space with a so-called "lazy" or passive protection rule (see [documentation](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPProtectContent))
* determine what IdP-supplied attributes you wish to support and configure mapping rules as desired to place them in headers (see [documentation](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPAttributeAccess))
* for Apache use, ensure that the SP is populating HTTP headers rather than environment variables (see [documentation](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPApacheConfig) on ShibUseHeaders)

Also think about your error handling requirements, particularly for dealing with missing attributes. Some discussion of this can be found [here](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPErrors).


Here is some partly outdated and incomplete documentation for hints on setup that might help, or might not:
* [How to Shibbolize Confluence Using Shibboleth 2.x](README-HOW_TO_SHIBBOLIZE_v2.x.md)
* [How to Shibbolize Confluence Using Shibboleth 1.3](README-HOW_TO_SHIBBOLIZE_v1.3.md)

#### Implementation Notes

* To find the appropriate version of the authenticator for your version of Confluence, see [Confluence Shibboleth Authenticator].
* If you are using a recent version of confluence, you'll want to use a more recent version of the authenticator (1.1+). Older versions of the authenticator were written for a pre-v2.2 version of confluence and extends DefaultAuthenticator instead of ConfluenceAuthenticator. [According to Atlassian](http://confluence.atlassian.com/display/DEV/Single+Sign-on+Integration+with+JIRA+and+Confluence): "For Confluence 2.2 and above you must extend com.atlassian.confluence.user.ConfluenceAuthenticator instead of the Seraph DefaultAuthenticator." And\- older versions of the authenticator use UserManager instead of the newer user-atlassian's UserAccessor to create users.
* The 1.0 version of the authenticator could fail authentication if you are using Oracle 10g and get a unique contraint error when two different nodes (using massive) try to create the same user at the same time from two different nodes. This was fixed in 1.1+.
* It has been suggested that the authenticator override the login(HttpServletRequest request, HttpServletResponse response) method instead of getUser(HttpServletRequest request, HttpServletResponse response). However login(...) never gets called during login (at least in 2.5.4 and using user-atlassian schema instead of the osuser schema), so that wouldn't work. getUser(...) gets called a lot, but it is always just pulling the user from session (and Confluence's own authenticator does the same). You'll see that if you turn on debug logging.
