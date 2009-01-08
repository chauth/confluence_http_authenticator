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
 * Modified 2009-01-05 to revamped the mapping processing mechanism to handle regex, purging roles, etc (SHBL-6) [Bruc Liong]
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
import com.atlassian.user.EntityException;
import com.atlassian.user.GroupManager;
import com.atlassian.confluence.user.UserPreferencesKeys;
import com.opensymphony.module.propertyset.PropertyException;
import com.atlassian.user.search.page.Pager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.security.Principal;
import java.io.File;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Date;

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
 * who don't have attributes to regain membership anymore (comma/semicolon
 * separated regex)</li>
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
 *
 * <li><strong>dynamicroles.auto_create_role</strong> - should new roles be
 * automatically created in confluence (and users assigned to it). Default to false
 *
 * <li><strong>dynamicroles.header.XXX</strong> - XXX is the name of the
 * HTTP header that will carry user's role information. Lists the mapper
 * names that are supposed to handle these roles. Mapper labels separated by
 * comma or semicolon. If this entry is empty or not existing, then no dynamic
 * role mapping loaded for this particular header. Example:
 * dynamicroles.header.SHIB-EP-ENTITLEMENT = mapper1, label5</li>
 * <li><strong>dynamicroles.mapper.YYY </strong> - YYY is the label name for the
 * mapper. This mapper is responsible of matching the input and processing
 * value transformation on the input. The output of the mapper is the role
 * supplied to confluence.See further examples in properties
 * file for details.
 * <ul><li><strong>match</strong> - regex for the mapper to match against
 * the given input</li>
 * <li><strong>casesensitive</strong> - should the matching performed by 'match'
 * be case sensitive. Default to true</li>
 * <li><strong>transform</strong> - a fix string replacement of the input
 * (e.g. the group or groups). when not specified, it will simply takes the
 * input value. roles as the result of matching input (separated by comma or
 * semicolon). parts of initial input can be used here in the form
 * of $0, $1...$N where $0 represents the whole input string, $1...N represent
 * regex groupings as used in 'match' regex</li>
 * </ul>
 * Example: <br/>
 * dynamicroles.mapper.label5.match = some\:example\:(.+)\:role-(.*) <br/>
 * dynamicroles.mapper.label5.transform = $1, $2, confluence-$2
 * </li>
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
            if (System.currentTimeMillis() < config.getConfigFileLastChecked() + config.
                getReloadConfigCheckInterval()) {
                return;
            }

            long configFileLastModified = new File(config.getConfigFile()).
                lastModified();

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
            //if (log.isDebugEnabled()) {
            //    log.debug("Assigning roles to user " + user.getName());
            //}

            String role;
            Group group;

            for (Iterator it = roles.iterator(); it.hasNext();) {
                role = it.next().toString().trim();

                if (role.length() == 0) {
                    continue;
                }

                if (log.isDebugEnabled()) {
                    log.debug("Assigning " + user.getName() + " to role " + role);
                }

                try {
                    group = getGroupManager().getGroup(role);
                    if (group == null) {
                        if (ShibAuthConfiguration.isAutoCreateGroup()) {
                            if (getGroupManager().isCreative()) {
                                group = getGroupManager().createGroup(role);
                            } else {
                                log.warn(
                                    "Cannot create role '" + role + "' due to permission issue.");
                                continue;
                            }
                        } else {
                            log.debug(
                                "Skipping autocreation of role '" + role + "'.");
                            continue; //no point of attempting to allocate user
                        }
                    }
                    getGroupManager().addMembership(group, user);
                } catch (Exception e) {
                    log.error(
                        "Attempted to add user " + user + " to role " + role + " but the role does not exist.",
                        e);
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
     * @param rolesToKeep keep these roles, otherwise everything else
     * mentioned in the purgeMappings can go.
     */
    private void purgeUserRoles(User user, Collection rolesToKeep) {
        if ((config.getPurgeMappings().size() == 0)) {
            if (log.isDebugEnabled()) {
                log.debug(
                    "No roles to purge specified, not purging any roles...");
            }
        } else {
            Pager p = null;
            if (log.isDebugEnabled()) {
                log.debug("Purging roles from user " + user.getName());
            }
            try {
                //get intersection of rolesInConfluence and rolesToKeep
                p = getGroupManager().getGroups(user);
                if (p.isEmpty()) {
                    log.debug("No roles available to be purged for this user.");
                    return;
                }
            } catch (EntityException ex) {
                log.error("Fail to fetch user's group list, no roles purged.",
                    ex);
            }

            Collection purgeMappers = config.getPurgeMappings();

            for (Iterator it = p.iterator(); it.hasNext();) {
                Group group = (Group) it.next();
                String role = group.getName();
                //log.debug("Checking group "+role+" for purging.");

                //TODO: case sensitive checks ! if confluence role was not created
                //by this pluggin then it may not match (e.g. HeLLo and hello)
                if (!rolesToKeep.contains(role)) {
                    //run through the purgeMappers for this role
                    for (Iterator it2 = purgeMappers.iterator(); it2.hasNext();) {
                        GroupMapper mapper = (GroupMapper) it2.next();

                        //max only 1 group output
                        String output = mapper.process(role);
                        if (output != null) {
                            try {
                                log.debug(
                                    "Removing user " + user.getName() + " from role " + role);
                                getGroupManager().removeMembership(group, user);
                                break;  //dont bother to continue with other purge mappers
                            } catch (Throwable e) {
                                log.error(
                                    "Error encountered in removing user " + user.
                                    getName() +
                                    " from role " + role, e);
                            }
                        }
                    }
                } else {
                    log.debug("Keeping role " + role + " for user " + user.
                        getName());
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
        Principal user = null;

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
                        "Error creating user " + userid + ". Will ignore and try to get the user (maybe it was already created)",
                        t);
                }

                user = getUser(userid);

                if (user == null) {
                    log.error(
                        "Error creating user " + userid + ". Got null user after attempted to create user (so it probably was not a duplicate).",
                        t);
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug(
                    "Configuration does NOT allow for creation of new user accounts, authentication will fail for " + userid);
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
            User userToUpdate = (User) user;
            boolean updated = false;

            if ((fullName != null) && !fullName.equals(
                userToUpdate.getFullName())) {
                if (log.isDebugEnabled()) {
                    log.debug("updating user fullName to '" + fullName + "'");
                }

                userToUpdate.setFullName(fullName);
                updated = true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(
                        "new user fullName is same as old one: '" + fullName + "'");
                }
            }

            if ((emailAddress != null) && !emailAddress.equals(userToUpdate.
                getEmail())) {
                if (log.isDebugEnabled()) {
                    log.debug(
                        "updating user emailAddress to '" + emailAddress + "'");
                }

                userToUpdate.setEmail(emailAddress);
                updated = true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(
                        "new user emailAddress is same as old one: '" + emailAddress + "'");
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
     * Updates last login and previous login dates. Originally contributed by Erkki Aalto and written by Jesse Lahtinen of (Finland) Technical University (http://www.tkk.fi) in SHBL-14.
     * Note bug in USER-254.
     */
    private void updateLastLogin(Principal principal) {

        //Set last login date

        // synchronize on the user name -- it's quite alright to update the property sets of two different users
        // in seperate concurrent transactions, but two concurrent transactions updateing the same user's property
        // set dies.
        //synchronized (userid.intern()) {
        // note: made a few slight changes to code- Gary.
        UserAccessor userAccessor = getUserAccessor();
        User user = (User) principal;
        String userId = user.getName();
        // TODO: Shouldn't synchronize, because that wouldn't help in a Confluence cluster (diff JVMs) for Confluence Enterprise/Confluence Massive. This should be added as a Confluence bug.
        synchronized (userId) {
            try {
                Date previousLoginDate = userAccessor.getPropertySet(user).
                    getDate(UserPreferencesKeys.PROPERTY_USER_LAST_LOGIN_DATE);
                if (previousLoginDate != null) {
                    try {
                        userAccessor.getPropertySet(user).remove(
                            UserPreferencesKeys.PROPERTY_USER_LAST_LOGIN_DATE);
                        userAccessor.getPropertySet(user).setDate(
                            UserPreferencesKeys.PROPERTY_USER_LAST_LOGIN_DATE,
                            new Date());
                        userAccessor.getPropertySet(user).remove(
                            UserPreferencesKeys.PROPERTY_USER_PREVIOUS_LOGIN_DATE);
                        userAccessor.getPropertySet(user).setDate(
                            UserPreferencesKeys.PROPERTY_USER_PREVIOUS_LOGIN_DATE,
                            previousLoginDate);
                    } catch (PropertyException ee) {
                        log.error(
                            "Problem updating last login date/previous login date for user '" + userId + "'",
                            ee);
                    }
                } else {
                    try {
                        userAccessor.getPropertySet(user).remove(
                            UserPreferencesKeys.PROPERTY_USER_LAST_LOGIN_DATE);
                        userAccessor.getPropertySet(user).setDate(
                            UserPreferencesKeys.PROPERTY_USER_LAST_LOGIN_DATE,
                            new Date());
                        userAccessor.getPropertySet(user).remove(
                            UserPreferencesKeys.PROPERTY_USER_PREVIOUS_LOGIN_DATE);
                        userAccessor.getPropertySet(user).setDate(
                            UserPreferencesKeys.PROPERTY_USER_PREVIOUS_LOGIN_DATE,
                            new Date());
                    } catch (PropertyException ee) {
                        log.error(
                            "There was a problem updating last login date/previous login date for user '" + userId + "'",
                            ee);
                    }
                }
            } catch (Exception e) {
                log.error(
                    "Can not retrieve the user ('" + userId + "') to set its Last-Login-Date!",
                    e);
            } catch (Throwable t) {
                log.error(
                    "Error while setting the user ('" + userId + "') Last-Login-Date!",
                    t);
            }
        }
    }

    //~--- get methods --------------------------------------------------------
    private String getEmailAddress(HttpServletRequest request) {
        String emailAddress = null;

        // assumes it is first value in list, if header is defined multiple times. Otherwise would need to call getHeaders()
        String headerValue = request.getHeader(config.getEmailHeaderName());

        // the Shibboleth SP sends multiple values as single value, separated by comma or semicolon
        List values = StringUtil.
            toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(headerValue);

        if (values != null && values.size() > 0) {

            // use the first email in the list
            emailAddress = (String) values.get(0);

            if (log.isDebugEnabled()) {
                log.debug("Got emailAddress '" + emailAddress + "' for header '" + config.
                    getEmailHeaderName() + "'");
            }

            if (config.isConvertToUTF8()) {
                String tmp = StringUtil.convertToUTF8(emailAddress);
                if (tmp != null) {
                    emailAddress = tmp;
                    if (log.isDebugEnabled()) {
                        log.debug("emailAddress converted to UTF-8 '" + emailAddress + "' for header '" + config.
                            getEmailHeaderName() + "'");
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
        List values = StringUtil.
            toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(headerValue);

        if (values != null && values.size() > 0) {

            // use the first full name in the list
            fullName = (String) values.get(0);

            if (log.isDebugEnabled()) {
                log.debug("Got fullName '" + fullName + "' for header '" + config.
                    getFullNameHeaderName() + "'");
            }

            if (config.isConvertToUTF8()) {
                String tmp = StringUtil.convertToUTF8(fullName);
                if (tmp != null) {
                    fullName = tmp;
                    if (log.isDebugEnabled()) {
                        log.debug("fullName converted to UTF-8 '" + fullName + "' for header '" + config.
                            getFullNameHeaderName() + "'");
                    }
                }
            }
        }

        if ((fullName == null) || (fullName.length() == 0)) {
            fullName = userid;
        }

        return fullName;
    }

    /**
     * This will populate accumulated (containing all roles discovered).
     *
     */
    private void getRolesFromHeader(HttpServletRequest request,
        Set accumulatedRoles) {
        Set attribHeaders = config.getGroupMappingKeys();

        // check if we're interested in some headers
        if (attribHeaders.isEmpty()) {
            return;
        }

        //purely for debugging purpose: this spits content of headers
        //for (Enumeration en =request.getHeaderNames(); en.hasMoreElements(); ) {
        //    String headerName = en.nextElement().toString();
        //    if (log.isDebugEnabled()) {
        //        log.debug("Header \"" + headerName
        //                  + " = " + request.getHeader(headerName)+"\"");
        //    }
        //}

        //process the headers by looking up only those list of registered headers
        for (Iterator headerIt = attribHeaders.iterator(); headerIt.hasNext();) {
            String headerName = headerIt.next().toString();
            for (Enumeration en = request.getHeaders(headerName); en.
                hasMoreElements();) {
                String headerValue = en.nextElement().toString();

                //shib sends values in semicolon separated, so split it up too
                List headerValues = StringUtil.
                    toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(
                    headerValue);
                for (int j = 0; j < headerValues.size(); j++) {
                    headerValue = (String) headerValues.get(j);
                    if (config.isConvertToUTF8()) {
                        String tmp = StringUtil.convertToUTF8(headerValue);
                        if (tmp != null) {
                            headerValue = tmp;
                        }
                    }
                    log.debug("Processing dynamicroles header=" + headerName +
                        ", value=" + headerValue);

                    Collection mappers = config.getGroupMappings(headerName);
                    boolean found = false;

                    for (Iterator mapperIt = mappers.iterator(); mapperIt.
                        hasNext();) {
                        GroupMapper mapper = (GroupMapper) mapperIt.next();

                        //we may get multiple groups returned by a single matched
                        //e.g. matching "XXX" --> "A, B, C"
                        String[] results = (String[]) StringUtil.
                            toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(
                            mapper.process(headerValue)).toArray(new String[0]);

                        for (int i = 0; i < results.length; i++) {
                            String result = results[i];
                            if (result.length() != 0) {

                                if (!accumulatedRoles.contains(result)) {
                                    accumulatedRoles.add(result);

                                    log.debug("Found role mapping from '" +
                                        headerValue + "' to '" + result + "'");
                                }
                                found = true;
                            }
                        }
                    }

                    if (!found) {
                        log.warn(
                            "No mapper capable of processing role value=" + headerValue);
                    }
                }
            }
        }
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
            log.debug(
                "Request made to " + request.getRequestURL() + " triggered this AuthN check");
        }

        HttpSession httpSession = request.getSession();
        Principal user;

        // Check if the user is already logged in
        if ((httpSession != null) && (httpSession.getAttribute(
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
        String fullName = getFullName(request, userid);
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
            if (ShibAuthConfiguration.isUpdateInfo()) {
                updateUser(user, fullName, emailAddress);
                if (config.isUpdateLastLogin()) {
                    this.updateLastLogin(user);
                }
            }
        }

        if (ShibAuthConfiguration.isUpdateRoles() || newUser) {
            Set roles = new HashSet();

            //fill up the roles
            getRolesFromHeader(request, roles);

            assignUserToRoles((User) user, config.getDefaultRoles());
            assignUserToRoles((User) user, roles);

            //make sure we don't purge default roles either
            roles.addAll(config.getDefaultRoles());
            purgeUserRoles((User) user, roles);
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
        Principal user = null;

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
        if (groupManager == null) {
            groupManager = (GroupManager) ContainerManager.getComponent(
                "groupManager");
        }
        return groupManager;
    }

    public void setGroupManager(GroupManager groupManager) {
        this.groupManager = groupManager;
    }
}
