/*
 Copyright (c) 2008, Shibboleth Authenticator for Confluence Team
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
 * Neither the name of the Shibboleth Authenticator for Confluence Team
   nor the names of its contributors may be used to endorse or promote
   products derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Modified 2008-12-03 to encorporate patch from Vladimir Mencl for SHBL-8 related to CONF-12158 (DefaultUserAccessor checks permissions before adding membership in 2.7 and later)
 * Modified 2008-07-29 to fix UTF-8 encoding [Helsinki University], made UTF-8 fix optional [Duke University]
 * Modified 2008-01-07 to add role mapping from shibboleth attribute (role) to confluence group membership. [Macquarie University - MELCOE - MAMS], refactor config loading, constants, utility method, and added configuration VO [Duke University]
 * Modified 2007-05-21 additional checks/logging and some small refactoring. Changed to use UserAccessor so should work with Confluence 2.3+ [Duke University]
 * Original version by Georgetown University. Original version (v1.0) can be found here: https://svn.middleware.georgetown.edu/confluence/remoteAuthn
 */

package shibauth.confluence.authentication.shibboleth;

//~--- JDK imports ------------------------------------------------------------

import com.atlassian.confluence.user.ConfluenceAuthenticator;
import com.atlassian.confluence.user.UserAccessor;
import com.atlassian.seraph.config.SecurityConfig;
import com.atlassian.user.Group;
import com.atlassian.user.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.atlassian.spring.container.ContainerManager;
import com.atlassian.user.GroupManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.security.Principal;
import java.util.*;
import java.io.File;

import com.atlassian.confluence.user.UserPreferencesKeys;
import com.opensymphony.module.propertyset.PropertyException;

/**
 * An authenticator that uses the REMOTE_USER header as proof of authentication.
 * <p/>
 * Configuration properties are looked for in
 * <i>/remoteUserAuthenticator.properties</i> on the classpath. This file
 * may contain the following properties:
 * <ul>
 * <li><strong>convert.to.utf8</strong> - Convert all incoming header values to UTF-8</li>
 * <li><strong>create.users</strong> - Indicates whether accounts should be
 * created for individuals the first they are encountered
 * (acceptable values: true/false)</li>
 * <li><strong>update.info</strong> - Indicates whether existing accounts
 * should have their name and email address information
 * updated when the user logs in (acceptable values: true/false)</li>
 * <li><strong>default.roles</strong> - The default roles newly created
 * accounts will be given (format: comma seperated list)</li>
 * <li><strong>purge.roles</strong> - Roles to be purged automatically of users
 * who don't have attributes to regain membership anymore</li>
 * <li><strong>reload.config</strong> - Automatically reload config when
 * change</li>
 * <li><strong>header.fullname</strong> - The name of the HTTP header that
 * will carry the full name of the user</li>
 * <li><strong>header.email</strong> - The name of the HTTP header that will
 * carry the email address for the user</li>
 *
 * <li><strong>update.roles</strong> - Indicates whether the existing accounts
 * should have their roles updated based on the header information. note: old
 * roles are not removed if the header doesn't contain it. (Acceptable values:
 * true/false. Default to false)</li>
 * <li><strong>header.dynamicroles.attributenames</strong> - The name of the
 * HTTP header that will carry the attribute name as indication of user's roles
 * (i.e. SHIB_EP_ENTITLEMENT). Case insensitive. Names separated by comma or
 * semicolon or space. If this entry is empty or not existing, then no dynamic
 * role mapping loaded</li>
 * <li><strong>header.dynamicroles.attributeValue1</strong> - The incoming
 * attribute value (from header.dynamicroles.attributenames headers) to be
 * mapped to group membership within confluence. See examples in properties
 * file for details.</li>
 * </ul>
 */
public class RemoteUserAuthenticator extends ConfluenceAuthenticator {

    //~--- static fields ------------------------------------------------------

    /**
     * Serial version UID
     */
    private static final long serialVersionUID = -5608187140008286795L;

    /**
     * Logger
     */
    private final static Log log =
        LogFactory.getLog(RemoteUserAuthenticator.class);

    private static ShibAuthConfiguration config;

    /** See SHBL-8, CONF-12158, and http://confluence.atlassian.com/download/attachments/192312/ConfluenceGroupJoiningAuthenticator.java?version=1 */
    private GroupManager groupManager = null;

    //~--- static initializers ------------------------------------------------

    /**
     * Initialize properties from property file
     */
    static {
        //TODO: use UI to configure if possible
        //TODO: use Spring to configure config loader, etc.

        config = ShibAuthConfigLoader.getShibAuthConfiguration(null);
    }

    /**
     * Check if the configuration file should be reloaded and reload the configuration.
     */
    private void checkReloadConfig() {

        if (config.isReloadConfig() && (config.getConfigFile() != null)) {
	    if (System.currentTimeMillis() < config.getConfigFileLastChecked() + config.getReloadConfigCheckInterval() ) {
	        return;
	    }
	    
	    long configFileLastModified = new File(config.getConfigFile()).lastModified();

	    if (configFileLastModified != config.getConfigFileLastModified()) {
	        log.debug("Config file has been changed, reloading");
		config = ShibAuthConfigLoader.getShibAuthConfiguration(config);
	    } else {
	        log.debug("Config file has not been changed, not reloading");
		config.setConfigFileLastChecked(System.currentTimeMillis());
	    }
	}
    }


    //~--- methods ------------------------------------------------------------

    /**
     * Assigns a user to the roles.
     *
     * @param user the user to assign to the roles.
     */
    private void assignUserToRoles(User user, Collection roles) {
        if (roles.size() == 0) {
            if (log.isDebugEnabled()) {
                log.debug("No roles specified, not adding any roles...");
            }
        } else {
            UserAccessor userAccessor = getUserAccessor();

            if (log.isDebugEnabled()) {
                log.debug("Assigning roles to user " + user.getName());
            }

            String role;
            Group  group;

            for (Iterator it = roles.iterator(); it.hasNext(); ) {
                role = it.next().toString().trim();

                if (role.length() == 0) {
                    continue;
                }

                if (log.isDebugEnabled()) {
                    log.debug("Assigning " + user.getName() + " to role "
                              + role);
                }

                try {
                    group = getGroupManager().getGroup(role);
                    getGroupManager().addMembership(group, user);
                } catch (Throwable e) {
                    log.error("Attempted to add user " + user + " to role "
                              + role + " but the role does not exist.", e);
                }
            }
        }
    }

    /**
     * Purge user from roles it no longer should have (based on current Shibboleth attributes).  
     * Remove the user from all roles listed in purgeRoles that are not
     * included in the current list of roles the user would get assigned to
     * based on the Shibboleth attributes received.
     *
     * @param user the user to assign to the roles.
     * @param rolesToPurge the roles the user should be purged from if they are not in rolesToKeep
     * @param rolesToKeep the roles the user should keep
     */
    private void purgeUserRoles(User user, Collection rolesToPurge, Collection rolesToKeep) {
	if ( (rolesToPurge == null) || (rolesToPurge.size() == 0) ) {
            if (log.isDebugEnabled()) {
                log.debug("No roles to purge specified, not purging any roles...");
            }
        } else {
            UserAccessor userAccessor = getUserAccessor();

            if (log.isDebugEnabled()) {
                log.debug("Purging roles from user " + user.getName());
            }

            String role;
            Group  group;

            for (Iterator it = rolesToPurge.iterator(); it.hasNext(); ) {
                role = it.next().toString().trim();

                if ( (role.length() == 0) || rolesToKeep.contains(role) ) {
		    log.debug("Not purging role " + role);
                    continue;
                }

                if (log.isDebugEnabled()) {
                    log.debug("Removing user " + user.getName() + " from role "
                              + role);
                }

                try {
                    group = getGroupManager().getGroup(role);
                    getGroupManager().removeMembership(group, user);
                } catch (Throwable e) {
                    log.error("Attempted to remove user " + user + " from role "
                              + role + " but the role does not exist.", e);
                }
            }
        }
    }

    /**
     * Change userid to lower case.
     *
     * @param userid userid to be changed
     * @return lower case version of it
     */
    private String convertUsername(String userid) {
        if (userid != null) {
            userid = userid.toLowerCase();
        }

        return userid;
    }

    /**
     * Creates a new user if the configuration allows it.
     *
     * @param userid user name for the new user
     * @return the new user
     */
    private Principal createUser(String userid) {
        UserAccessor userAccessor = getUserAccessor();
        Principal    user         = null;

        if (config.isCreateUsers()) {
            if (log.isInfoEnabled()) {
                log.info("Creating user account for " + userid);
            }

            try {
                user = userAccessor.createUser(userid);
            } catch (Throwable t) {

                // Note: just catching EntityException like we used to do didn't
                // seem to cover Confluence massive with Oracle
                if (log.isDebugEnabled()) {
                    log.debug(
                        "Error creating user " + userid
                        + ". Will ignore and try to get the user (maybe it was already created)", t);
                }

                user = getUser(userid);

                if (user == null) {
                    log.error(
                        "Error creating user " + userid
                        + ". Got null user after attempted to create user (so it probably was not a duplicate).", t);
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug(
                    "Configuration does NOT allow for creation of new user accounts, authentication will fail for "
                    + userid);
            }
        }

        return user;
    }

    /**
     * Initialize properties
     *
     * @param params
     * @param config
     */
    public void init(Map params, SecurityConfig config) {
        super.init(params, config);
    }

    private void updateUser(Principal user, String fullName,
                            String emailAddress) {
        UserAccessor userAccessor = getUserAccessor();

        // If we have new values for name or email, update the user object
        if ((user != null) && (user instanceof User)) {
            User    userToUpdate = (User) user;
            boolean updated      = false;

            if ((fullName != null)
                    &&!fullName.equals(userToUpdate.getFullName())) {
                if (log.isDebugEnabled()) {
                    log.debug("updating user fullName to '" + fullName + "'");
                }

                userToUpdate.setFullName(fullName);
                updated = true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("new user fullName is same as old one: '"
                              + fullName + "'");
                }
            }

            if ((emailAddress != null)
                    &&!emailAddress.equals(userToUpdate.getEmail())) {
                if (log.isDebugEnabled()) {
                    log.debug("updating user emailAddress to '" + emailAddress
                              + "'");
                }

                userToUpdate.setEmail(emailAddress);
                updated = true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("new user emailAddress is same as old one: '"
                              + emailAddress + "'");
                }
            }

            if (updated) {
                try {
                    userAccessor.saveUser(userToUpdate);
                } catch (Throwable t) {
                    log.error("Couldn't update user " + userToUpdate.getName(),
                              t);
                }
            }
        }
    }

    /**
     * Updates last login and previous login dates. Contributed by Erkki Aalto and written by Juha Ojaluoma.
     *
     * @author Juha Ojaluoma
     */
    private void updateLastLogin(Principal principal) {

        //Set last login date

        // synchronize on the user name -- it's quite alright to update the property sets of two different users
        // in seperate concurrent transactions, but two concurrent transactions updateing the same user's property
        // set dies.
        //synchronized (userid.intern()) {
        // note: made a few slight changes to code- Gary.
        UserAccessor userAccessor = getUserAccessor();
        User user = (User)principal;
        String userId = user.getName();
        // TODO: Shouldn't synchronize, because that wouldn't help in a Confluence cluster (diff JVMs) for Confluence Enterprise/Confluence Massive. This should be added as a Confluence bug.
        synchronized (userId) {
            try {
                Date previousLoginDate = userAccessor.getPropertySet(user).getDate(UserPreferencesKeys.PROPERTY_USER_LAST_LOGIN_DATE);
                if (previousLoginDate != null) {
                    try {
                        userAccessor.getPropertySet(user).remove(UserPreferencesKeys.PROPERTY_USER_LAST_LOGIN_DATE);
                        userAccessor.getPropertySet(user).setDate(UserPreferencesKeys.PROPERTY_USER_LAST_LOGIN_DATE, new Date());
                        userAccessor.getPropertySet(user).remove(UserPreferencesKeys.PROPERTY_USER_PREVIOUS_LOGIN_DATE);
                        userAccessor.getPropertySet(user).setDate(UserPreferencesKeys.PROPERTY_USER_PREVIOUS_LOGIN_DATE,previousLoginDate);
                    }
                    catch (PropertyException ee) {
                        log.error("Problem updating last login date/previous login date for user '" + userId + "'", ee);
                    }
                } else {
                    try {
                        userAccessor.getPropertySet(user).remove(UserPreferencesKeys.PROPERTY_USER_LAST_LOGIN_DATE);
                        userAccessor.getPropertySet(user).setDate(UserPreferencesKeys.PROPERTY_USER_LAST_LOGIN_DATE, new Date());
                        userAccessor.getPropertySet(user).remove(UserPreferencesKeys.PROPERTY_USER_PREVIOUS_LOGIN_DATE);
                        userAccessor.getPropertySet(user).setDate(UserPreferencesKeys.PROPERTY_USER_PREVIOUS_LOGIN_DATE, new Date());
                    }
                    catch (PropertyException ee) {
                        log.error("There was a problem updating last login date/previous login date for user '" + userId + "'", ee);
                    }
                }
            }
            catch (Exception e) {
                log.error("Can not retrieve the user ('" + userId + "') to set its Last-Login-Date!", e);
            }
            catch (Throwable t) {
                log.error("Error while setting the user ('" + userId + "') Last-Login-Date!", t);
            }
        }
    }

    //~--- get methods --------------------------------------------------------

    private String getEmailAddress(HttpServletRequest request) {
        String emailAddress = null;

        // assumes it is first value in list, if header is defined multiple times. Otherwise would need to call getHeaders()
        String headerValue = request.getHeader(config.getEmailHeaderName());

        // the Shibboleth SP sends multiple values as single value, separated by comma or semicolon
        List values = StringUtil.toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(headerValue);

        if (values!=null && values.size()>0) {

            // use the first email in the list
            emailAddress = (String)values.get(0);

            if (log.isDebugEnabled()) {
                log.debug("Got emailAddress '" + emailAddress + "' for header '"
                      + config.getEmailHeaderName() + "'");
            }

            if (config.isConvertToUTF8()) {
                String tmp = StringUtil.convertToUTF8(emailAddress);
                if (tmp != null) {
                    emailAddress = tmp;
                    if (log.isDebugEnabled()) {
                        log.debug("emailAddress converted to UTF-8 '" + emailAddress + "' for header '"
                          + config.getEmailHeaderName() + "'");
                    }
                }
            }
        }

        if ((emailAddress != null) && (emailAddress.length() > 0)) {
            emailAddress = emailAddress.toLowerCase();
        }

        return emailAddress;
    }

    private String getFullName(HttpServletRequest request, String userid) {
        String fullName = null;

        // assumes it is first value in list, if header is defined multiple times. Otherwise would need to call getHeaders()
        String headerValue = request.getHeader(config.getFullNameHeaderName());

        // the Shibboleth SP sends multiple values as single value, separated by comma or semicolon
        List values = StringUtil.toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(headerValue);

        if (values!=null && values.size()>0) {

            // use the first full name in the list
            fullName = (String)values.get(0);

            if (log.isDebugEnabled()) {
            log.debug("Got fullName '" + fullName + "' for header '"
                      + config.getFullNameHeaderName() + "'");
            }

            if (config.isConvertToUTF8()) {
                String tmp = StringUtil.convertToUTF8(fullName);
                if (tmp != null) {
                    fullName = tmp;
                    if (log.isDebugEnabled()) {
                        log.debug("fullName converted to UTF-8 '" + fullName + "' for header '"
                          + config.getFullNameHeaderName() + "'");
                    }
                }
            }
        }

        if ((fullName == null) || (fullName.length() == 0)) {
            fullName = userid;
        }

        return fullName;
    }

    private Collection getRolesFromHeader(HttpServletRequest request) {

        Set attribHeaders = config.getAttribHeaders();

        // check if we're interested in some headers
        if (attribHeaders.isEmpty()) {
            return Collections.emptyList();
        }

        // effective roles as in presented in headers if it existed in
        // mapRoleNames
        Set dynamicRoles = new HashSet();

        for (Enumeration en =
                request.getHeaderNames(); en.hasMoreElements(); ) {

            String headerName     = en.nextElement().toString();
            String trimmedLowercasedHeaderName = headerName.trim().toLowerCase();

            if (log.isDebugEnabled()) {
                log.debug("Analyzing header \"" + headerName
                          + "\" for a mapped role = "
                          + request.getHeader(headerName));
            }

            // see if this header is something we'd be interested in
            if (attribHeaders.contains(trimmedLowercasedHeaderName)) {
                Enumeration headerValues = request.getHeaders(headerName);

                if (headerValues!=null) {

                    while (headerValues.hasMoreElements()) {
                        String headerValue = (String)headerValues.nextElement();

                        if (headerValue!=null) {

                            if (config.isConvertToUTF8()) {
                                String tmp = StringUtil.convertToUTF8(headerName);
                                if (tmp != null) {
                                    headerValue = tmp;
                                    if (log.isDebugEnabled()) {
                                        log.debug("header value converted to UTF-8 '" + headerValue + "' for header '" +
                                                trimmedLowercasedHeaderName + "'");
                                    }
                                }
                            }

                            // the Shibboleth SP sends multiple values as single value, separated by comma or semicolon
                            List roles = StringUtil.toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(headerValue);

                            for (int i = 0; i < roles.size(); i++) {

                                // According to Bruc Liong, this is case-insensitive to make it easier on the admin.

                                String lowercaseRole = ((String)roles.get(i)).toLowerCase();

                                List confluenceGroups = (List) config.getMapRole().get(lowercaseRole);

                                if (confluenceGroups != null) {
                                    dynamicRoles.addAll(confluenceGroups);

                                    if (log.isDebugEnabled()) {
                                        StringBuffer confRoles = new StringBuffer();
                                        for(int j=confluenceGroups.size()-1; j>-1; j--){
                                            confRoles.append(confluenceGroups.get(j).toString());
                                            if (j != 0) {
                                                confRoles.append(",");
                                            }
                                        }
                                        if (log.isDebugEnabled()) {
                                            log.debug("Mapping role \"" + lowercaseRole + "\" to \""
                                                  + confRoles + "\"");
                                        }
                                    }
                                }
                            }
                        }
                        else {
                            if (log.isDebugEnabled()) {
                                log.debug("One of header values for headerName '" + headerName +
                                        "' was null, so was ignored");
                            }
                        }
                    }
                }
            }
        }

        //clean up a bit, in case these came into the list
        dynamicRoles.remove(null);
        dynamicRoles.remove("");

        return dynamicRoles;
    }

    // Tried overriding login(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse), but
    // it doesn't get called at all. That sucks because this method can often be called > 20 times per page.

    /**
     * @see com.atlassian.seraph.auth.Authenticator#getUser(
     *      javax.servlet.http.HttpServletRequest,
     *      javax.servlet.http.HttpServletResponse)
     *
     * @param request
     * @param response
     *
     * @return
     */
    public Principal getUser(HttpServletRequest request,
                             HttpServletResponse response) {
        if (log.isDebugEnabled()) {
            log.debug("Request made to " + request.getRequestURL()
                      + " triggered this AuthN check");
        }

        HttpSession httpSession = request.getSession();
        Principal   user;

        // Check if the user is already logged in
        if ((httpSession != null)
                && (httpSession.getAttribute(
                    ConfluenceAuthenticator.LOGGED_IN_KEY) != null)) {
            user = (Principal) httpSession.getAttribute(
                ConfluenceAuthenticator.LOGGED_IN_KEY);

            if (log.isDebugEnabled()) {
                log.debug(user.getName() + " already logged in, returning.");
            }

            return user;
        }

        // Since they aren't logged in, get the user name from
        // the REMOTE_USER header
        String userid = request.getRemoteUser();

        if ((userid == null) || (userid.length() <= 0)) {
            if (log.isDebugEnabled()) {
                log.debug(
                    "Remote user was null or empty, can not perform authentication");
            }

            return null;
        }

	// Now that we know we will be trying to log the user in, 
	// let's see if we should reload the config file first
	checkReloadConfig();

        // Convert username to all lowercase
        userid = convertUsername(userid);

        // Pull name and address from headers
        String fullName     = getFullName(request, userid);
        String emailAddress = getEmailAddress(request);

        // Try to get the user's account based on the user name
        user = getUser(userid);

        boolean newUser = false;

        // User didn't exist or was problem getting it. we'll try to create it
        // if we can, otherwise will try to get it again.
        if (user == null) {
            user = createUser(userid);

            if (user != null) {
                newUser = true;
                updateUser(user, fullName, emailAddress);
                if (config.isUpdateLastLogin()) {
                    this.updateLastLogin(user);
                }
            }
        } else {
            if (config.isUpdateInfo()) {
                updateUser(user, fullName, emailAddress);
                if (config.isUpdateLastLogin()) {
                    this.updateLastLogin(user);
                }
            }
        }

        if (config.isUpdateRoles() || newUser) {
	    Collection rolesFromHeader = getRolesFromHeader(request);
            assignUserToRoles((User) user, config.getDefaultRoles());
            assignUserToRoles((User) user, rolesFromHeader);
	    purgeUserRoles((User) user, config.getPurgeRoles(), rolesFromHeader);
        }

        // Now that we have the user's account, add it to the session and return
        if (log.isDebugEnabled()) {
            log.debug("Logging in user " + user.getName());
        }

        request.getSession().setAttribute(
            ConfluenceAuthenticator.LOGGED_IN_KEY, user);
        request.getSession().setAttribute(
            ConfluenceAuthenticator.LOGGED_OUT_KEY, null);

        return user;
    }

    /**
     * {@inheritDoc}
     *
     * @param userid
     *
     * @return
     */
    public Principal getUser(String userid) {
        if (log.isDebugEnabled()) {
            log.debug("Getting user " + userid);
        }

        UserAccessor userAccessor = getUserAccessor();
        Principal    user         = null;

        try {
            user = userAccessor.getUser(userid);

            if (user == null) {
                if (log.isDebugEnabled()) {
                    log.debug("No user account exists for " + userid);
                }
            }
        } catch (Throwable t) {
            log.error("Error getting user", t);
        }

        return user;
    }

    /**
     * This is the Atlassian-suggested way of handling the issue noticed by Vladimir Mencl in Confluence 2.9.2 (but not in 2.9) where
     * addMembership(...) was failing, and apparently it failed because it was expecting that GroupManager was not returning an instance.
     * I don't think we have a spring config (bean defined in spring config) for this authenticator yet, so wouldn't be set by that or autowiring I guess.
     * The solution provided by Vladimir Mencl and referred to by Matt Ryall in CONF-12158 is similar to that of the older ConfluenceGroupJoiningAuthenticator.java
     * provided with Confluence that Matt attached here: http://confluence.atlassian.com/download/attachments/192312/ConfluenceGroupJoiningAuthenticator.java?version=1
     * See also SHBL-8. Thanks much to Vladimir Mencl for this patch.
     */
    public GroupManager getGroupManager() {
        if (groupManager == null)
        {
          groupManager = (GroupManager) ContainerManager.getComponent(
              "groupManager");
        }
        return groupManager;
    }

    public void setGroupManager(GroupManager groupManager) {
        this.groupManager = groupManager;
    }


}
