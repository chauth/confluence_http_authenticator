=== Version History

    2.3.0   23 Aug 2013 Changes by Gary Weaver:
    
        #2 Fix local login with patch - contributed by Erkki Aalto
    
        #10 Get shib attributes from environment variables first if available - contributed by Joakim Lundin (@iceglow)
        
        BSD     remoteUserAuth-2.3.0.jar, remoteUserAuthenticator.properties

    2.2.0   4 Mar 2013  Changes by William Schneider:
    
        Support for Confluence 5.0.
        
        Changes by Gary Weaver:
        
        pom.xml cleanup, doc/etc. cleanup and changes due to migration to GitHub.
        
        BSD     remoteUserAuth-2.2.0.jar, remoteUserAuthenticator.properties

    2.1.16  3 Sep 2012  Changes by Gary Weaver:

        SHBL-66: Added support for remember me cookie, basic auth support, api changes.

        BSD     remoteUserAuth-2.1.16.jar, remoteUserAuthenticator.properties
    
    2.1.15  3 Sep 2012  Changes by Gary Weaver:

        SHBL-63: Adding local user login changes contributed by Georg Kallidis.

        BSD     remoteUserAuth-2.1.15.jar, remoteUserAuthenticator.properties
    
    2.1.14  22 Mar 2012     Changes by Gary Weaver:

        SHBL-61, SHBL-62: Fixing local user login, login events, changes to logging.

        BSD     remoteUserAuth-2.1.14.jar, remoteUserAuthenticator.properties
    
    2.1.13  16 Mar 2012     Changes by Gary Weaver:

        SHBL-59, SHBL-60, SHBL-61: Users marked as inactive should now not be able to login. Adding login events sent to Confluence. Additional logging.

        BSD     remoteUserAuth-2.1.13.jar, remoteUserAuthenticator.properties
    
    2.1.11  9 Feb 2012  Changes by Gary Weaver:

        SHBL-57: Confluence 4.1.x+ compatibility. Thanks to John Hare for all of his assistance!

        BSD     remoteUserAuth-2.1.11.jar, remoteUserAuthenticator.properties
    
    2.1.9   8 Feb 2012  Changes by Gary Weaver:

        SHBL-50, SHBL-52, SHBL-53, SHBL-55, SHBL-56: Confluence 4.1.x+ compatibility. Thanks to Mathias Kresin for the info on using getUserFromSession(request) vs. request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY) as described here and as mentioned in comment in SHBL-53.

        BSD     remoteUserAuth-2.1.9.jar, remoteUserAuthenticator.properties
    
    2.0.1   19 Apr 2011     Changes by Gary Weaver:

        SHBL-47 and SHBL-48: Confluence 3.5.x compatibility

        BSD     remoteUserAuth-2.0.1.jar, remoteUserAuthenticator.properties
    
    1.7.4   31 Jan 2011     Changes by Gary Weaver:

        SHBL-46: Unwrap HttpServletRequest only if necessary
        Changes by Elliot Kendall:
        SHBL-27: Attempt to update last login time

        BSD     remoteUserAuth-1.7.4.jar, remoteUserAuthenticator.properties
    
    1.7.3   30 Nov 2010     Changes by Elliot Kendall:

        SHBL-36: Check for null return from getResourceAsStream and raise an exception
        SHBL-38: Support reading username from a configurable header
        SHBL-40: Explicitly obtain a non-SecurityHttpRequestWrapper request object to use to determine remote user, for Confluence 3.4 compatibility (per a suggestion by Jesse Lahtinen)
        SHBL-41: Support not forcing username to lowercase

        BSD     remoteUserAuth-1.7.3.jar, remoteUserAuthenticator.properties

    1.7.2   28 Sep 2010     Changes by Elliot Kendall:

        SHBL-37: Fix a NPE when using LDAP as a user repository, and no LDAP user matches REMOTE_USER.
        Changes by Gary Weaver:
        SHBL-34: attempt to fix issue with createUser = false scenario noticed by Adam Cohen and with help on patch by Bruce Liong and Gary Weaver
        SHBL-31: updated pom.xml to not use older developer repo

        BSD     remoteUserAuth-1.7.2.jar, remoteUserAuthenticator.properties

    1.7.1   21 Oct 2009     Changes by Gary Weaver:

        SHBL-29: Reincorporating UTF-8                              code from Juha Ojaluoma/Helsinki. If anyone wishes to change this, please discuss with Juha O./Erkki Aalto.

        BSD     remoteUserAuth-1.7.1.jar, remoteUserAuthenticator.properties

    1.7     14 Oct 2009     Changes by Juhani Gurney:

        SHBL-24: Local accounts now supported as long as ShibAuthFilter is not used
        Changes by Gary Weaver:
        SHBL-28 - adding regexp matching for full name for Freie Universität Berlin so that they could use our plugin without mods
        SHBL-24 - fixing authentication for local accounts by integrating patch by Freie Universität Berlin and making it optional to use ShibLoginFilter, but turning off support for it by default. (Note: this additionally required later fix contributed by Juhani Gurney.)

        BSD     remoteUserAuth-1.7.jar, remoteUserAuthenticator.properties

    1.6     12 Aug 2009     Changes by Bruc Liong:

        Solution to SHBL-25. An option is provided to allow remote user to be transformed/mapped based on regex to be used by Confluence userid. Read config properties file for example and detail.
        Changes by Gary Weaver:
        SHBL-26 - integrating patch from Michael Gettes not to try to update read-only users. Also had to enable debug of HTTP Headers and regexp match so that USC could debug their headers/regexp. Cleaned up logging a bit around those so that all HTTP headers logged at once (which might be more helpful in higher traffic).

        BSD     remoteUserAuth-1.6.jar, remoteUserAuthenticator.properties

    1.5.1   26 June 2009    Changes by Gary Weaver:

        SHBL-23 - No mapper capable of processing role message should be logged DEBUG not WARN

        BSD     remoteUserAuth-1.5.1.jar, remoteUserAuthenticator.properties

    1.5     24 June 2009    Changes by Gary Weaver:

        SHBL-21 - applying patch contributed from Michael Gettes because call to hasMembership and only calling addMembership when needed he determined was faster than only calling addMembership fix for SHBL-20 and some other possible config related issues not yet noticed. changed from using static values in config to instance. config instance itself is static and gets reloaded, so we don't want static member variables in the configuration instance itself, unless I'm missing something. we should consider moving to spring config for v2.0. config is a little out of hand now.
        Resolved SHBL-18. Added null checks for header.fullname and header.email in config and updated config.
        Per some recent commits, there seems to now be a dependency on a newer version of seraph than may be included in earlier versions of confluence. In fact, upping the confluence version (tried several versions) didn't seem to include these. I looked at Atlassian's pom for confluence and it appears that only an earlier version of seraph (not atlassian-seraph) was referenced in earlier builds, and later builds don't include the version they may/may not use. We may end up needing to make changes to the code to make it work with older versions of Confluence, or we may need to change the dependencies (and maybe change versions?) to have a scope that would include these jars in the plugin rather than expect that Confluence provide them, in which case compatibility could be an ongoing issue.
        Implemented patch submitted by Erkki Aalto written by Juha Ojaluoma for SHBL-14. Note that USER-254 possible bug related to this feature. This feature implements a new config option called update.last.login.date (true/false) in config that sets properties for the user in os_propertyentry even if not using osuser schema otherwise according to Erkki. Also updated License text.
        Changes by Bruc Liong:
        Resolved SHBL-16, hopefully improving response time slightly for SHBL-15. Made updateLastLogin option optional. We're letting confluence to take care of that now. You will need to use the provided LoginFilter, by making the following change to web.xml:
        <filter-name>login</filter-name>
        <!-- <filter-class>com.atlassian.seraph.filter.LoginFilter</filter-class>  -->
        <filter-class>shibauth.confluence.authentication.shibboleth.ShibLoginFilter</filter-class>
        Failure to use this Login Filter in web.xml will produce previous behaviour (i.e. before SHBL-16 fix; updateLastLogin is fully obeyed).
        Provided option dynamicroles.output.tolowercase to convert all group output to lower case by default.
        Changed StringUtil.convertToUTF8 to have new String(getBytes("UTF-8                             "),"UTF-8                             ") to see if UTF-8                              conversion working, otherwise byte by byte conversion needs to be put in place.
        Revamp of group mapping per SHBL-6. Includes the following capabilities:
            Regex mapping of group memberships to add based on headers
            Inspects only necessary headers for group mapping
            Removing group memberships with regex
            Multiple regex/mappers can be specified per header

        BSD     remoteUserAuth-1.5.jar, remoteUserAuthenticator.properties

    1.4     19 Dec 2008     Changes made by Vladimir Mencl to implemented two new features requested in SHBL-10 and SHBL-11:

        SHBL-10: Addresses the issue where users dynamically assigned to groups would stay in these groups even when they no longer have (temporary) attributes that originally gained them the membership (such as codes of courses they are taking). Now, such groups can be specified with purge.roles, such as:
        purge.roles=course-ABCD123,course-DCBA321
        (Requires update.roles=true)
        SHBL-11: Restarting Confluence after adding a dynamic mapping would have too much impact on a production environment. With this feature, the module checks for changes to the configuration file (remoteAuthentication.propeties) on each user login and reloads the file if needed. It is also possible to set a minimal delay between the checks (in milliseconds, defaults to 0). To activate this feature, add the following to your configuration file:
        reload.config=true
        reload.config.check.interval=5000

        BSD     remoteUserAuth-1.4.jar, remoteUserAuthenticator.properties

    1.3.1   5 Dec 2008  Changes made by Juha Ojaluoma for SHBL-5 to convert full name to UTF-8                             . Changes made by Gary Weaver and Bruc Liong to convert all header values to UTF-8                             . Changes made by Gary Weaver for SHBL-7 to add ability to handle multiple headers. Changes made Vladimir Mencl for SHBL-8 to fix issue with adding users to groups noticed in Confluence 2.9.2, along with subsequent fix in SHBL-9. Changes made by Gary Weaver to use BSD open-source license instead of Apache open-source license. Changes made by Gary Weaver to mavenize project and refactor. Should work in prior versions (Confluence 2.3+), but needs testing. Tested in Confluence 2.9.2.     BSD     remoteUserAuth-1.3.1.jar, remoteUserAuthenticator.properties

    1.2     7 Mar 2008  Changes made by Bruc Liong of the Macquarie E-Learning Centre Of Excellence (MELCOE) to allow optional mapping of the values of 0-to-many HTTP Headers (fed by shib attributes) to Confluence group names (see properties file for how to do this). Changes made by Gary Weaver of Duke University to refactor config loading, constants, utility method, and added configuration VO.   Apache  remoteUserAuth-1.2.jar, remoteUserAuthenticator.properties

    1.1     10 Dec 2007     Based on modifications by Gary Weaver of Duke University for Confluence 2.3-2.6.x along with additional checks/logging and some small refactoring. Version 1.1 should work with Confluence 2.3-2.6.x and possibly later versions.   Apache  remoteUserAuth-1.1.jar, remoteUserAuthenticator.properties

    1.0     24 May 2007     Written by Chad LaJoie of Georgetown University and provided via https://svn.middleware.georgetown.edu/confluence/remoteAuthn/ and via in Internet2's confluence instance "spaces" at https://spaces.internet2.edu/display/SHIB/ShibbolizedConfluence. Version 1.0 worked with some Confluence versions prior to 2.3 (at least 2.2.x) and possibly worked up to Confluence 2.5.x. 