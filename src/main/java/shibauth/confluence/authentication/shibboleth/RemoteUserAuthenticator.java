/*
 Copyright (c) 2008-2011, Shibboleth Authenticator for Confluence Team
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
 * Modified 2009-09-29 call super.login() if REMOTE_USER wasn't set to enable local Confluence login (SHBL-24) [Juhani Gurney]
 * Modified 2009-01-22 to make use of ShibLoginFilter (SHBL-16), make updateLastLogin as optional [Bruc Liong]
 * Modified 2009-01-05 to revamp the mapping processing mechanism to handle regex, purging roles, etc (SHBL-6) [Bruc Liong]
 * Modified 2008-12-03 to encorporate patch from Vladimir Mencl for SHBL-8 related to CONF-12158 (DefaultUserAccessor checks permissions before adding membership in 2.7 and later)
 * Modified 2008-07-29 to fix UTF-8 encoding [Helsinki University], made UTF-8 fix optional [Duke University]
 * Modified 2008-01-07 to add role mapping from shibboleth attribute (role) to confluence group membership. [Macquarie University - MELCOE - MAMS], refactor config loading, constants, utility method, and added configuration VO [Duke University]
 * Modified 2007-05-21 additional checks/logging and some small refactoring. Changed to use UserAccessor so should work with Confluence 2.3+ [Duke University]
 * Original version by Georgetown University. Original version (v1.0) can be found here: https://svn.middleware.georgetown.edu/confluence/remoteAuthn
 */

package shibauth.confluence.authentication.shibboleth;

import com.atlassian.spring.container.ContainerManager;

//~--- JDK imports ------------------------------------------------------------
import com.atlassian.confluence.user.ConfluenceAuthenticator;
import com.atlassian.crowd.embedded.impl.ImmutableUser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.atlassian.user.EntityException;
import com.atlassian.user.GroupManager;
import com.atlassian.confluence.event.events.security.LoginEvent;
import com.atlassian.confluence.event.events.security.LoginFailedEvent;
import com.atlassian.confluence.user.UserAccessor;
import com.atlassian.confluence.user.UserPreferencesKeys;
import com.atlassian.confluence.user.crowd.EmbeddedCrowdBootstrap;
import com.atlassian.crowd.dao.application.ApplicationDAO;
import com.atlassian.crowd.embedded.api.CrowdDirectoryService;
import com.atlassian.crowd.embedded.api.CrowdService;
import com.atlassian.crowd.embedded.api.Directory;
import com.atlassian.crowd.embedded.api.DirectoryType;
import com.atlassian.crowd.embedded.api.Group;
import com.atlassian.crowd.embedded.api.User;
import com.atlassian.crowd.event.user.UserAuthenticatedEvent;
import com.atlassian.crowd.exception.ApplicationNotFoundException;
import com.atlassian.crowd.manager.application.ApplicationService;
import com.atlassian.crowd.model.application.Application;
import com.atlassian.event.api.EventPublisher;
import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.user.search.page.Pager;
import com.opensymphony.module.propertyset.PropertyException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.ServletRequestWrapper;
import java.security.Principal;
import java.io.File;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;

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
 * <li><strong>header.remote_user</strong> - The name of the HTTP header that will
 * carry the username</li>
 *
 * <li><strong>username.convertcase</strong> - Indicates whether usernames
 * should be converted to lowercase before use</li>
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

    //~--- static initializers ------------------------------------------------
    /**
     * Initialize properties from property file
     */


    static {
        //TODO: use UI to configure if possible
        //TODO: use Spring to configure config loader, etc.

        config = ShibAuthConfigLoader.getShibAuthConfiguration(null);
    }

    public RemoteUserAuthenticator() {
        // SHBL-48/CONF-22266 - Authenticators in Confluence 3.5:
        // * Cannot have Atlassian beans injected via Spring (see comment late in CONF-22266)
        // * Authenticators must be classloaded and cannot be Atlassian plugins v1 or v2 (see comment late in CONF-22266), so
        //   neither setter nor constructor injection of GroupManager and CrowdService would work.
        // * Can only get bean instances using ContainerManager after the beans have been constructed, so cannot be done here in constructor.
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
    private void assignUserToRoles(Principal user, Collection roles) {
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
            
            CrowdService crowdService = getCrowdService();
			if (crowdService==null) {
				throw new RuntimeException("crowdService was not wired in RemoteUserAuthenticator");
	        }

            for (Iterator it = roles.iterator(); it.hasNext();) {
                role = it.next().toString().trim();

                if (role.length() == 0) {
                    continue;
                }

                if (log.isDebugEnabled()) {
                    log.debug("Assigning " + user.getName() + " to role " + role);
                }

                group = crowdService.getGroup(role);
                if (group == null) {
                    if (config.isAutoCreateGroup()) {
                        try {
                            group = crowdService.addGroup(group);
                        }
                        catch (Throwable t) {
                            log.error("Cannot create role '" + role + "'.", t);
                            continue;
                        }
                    } else {
                        log.debug(
                            "Skipping autocreation of role '" + role + "'.");
                        continue; //no point of attempting to allocate user
                    }
                }

                User crowdUser = crowdService.getUser(user.getName());
                if (crowdUser == null) {
                    log.warn("Could not find user '" + user.getName() + "' to add them to role '" + role + "'.");
                }
                else if (crowdService.isUserMemberOfGroup(crowdUser, group)) {
                    log.debug("Skipping " + user.getName() + " to role " + role + " - already a member");
                }
                else {
                    try {
                        crowdService.addUserToGroup(crowdUser, group);
                    }
                    catch (Throwable t) {
                        log.error("Failed to add user " + user + " to role " + role + ".", t);
                    }
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
    private void purgeUserRoles(Principal user, Collection rolesToKeep) {
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
            
			CrowdService crowdService = getCrowdService();
            if (crowdService==null) {
				throw new RuntimeException("crowdService was not wired in RemoteUserAuthenticator");
	        }

            User crowdUser = crowdService.getUser(user.getName());


            Collection purgeMappers = config.getPurgeMappings();

            for (Iterator it = p.iterator(); it.hasNext();) {
                Group group = (Group) it.next();
                String role = group.getName();

                if (!StringUtil.containsStringIgnoreCase(rolesToKeep,role)) {
                    //run through the purgeMappers for this role
                    for (Iterator it2 = purgeMappers.iterator(); it2.hasNext();) {
                        GroupMapper mapper = (GroupMapper) it2.next();

                        //max only 1 group output
                        String output = mapper.process(role);
                        if (output != null) {
                            try {
                                if (crowdService.isUserMemberOfGroup(crowdUser, group)) {
                                    log.debug("Removing user " + user.getName() + " from role " + role);
                                    crowdService.removeUserFromGroup(crowdUser, group);
                                    break;
                                }
                            } catch (Throwable t) {
                                log.error(
                                    "Error encountered in removing user " + user.
                                    getName() +
                                    " from role " + role, t);
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

    private void updateUser(Principal user, String fullName,
        String emailAddress) {

        // If we have new values for name or email, update the user object
        if (user != null) {
            boolean updated = false;

            CrowdService crowdService = getCrowdService();
            if (crowdService==null) {
				throw new RuntimeException("crowdService was not wired in RemoteUserAuthenticator");
	        }
            User crowdUser = crowdService.getUser(user.getName());
            ImmutableUser.Builder userBuilder = new ImmutableUser.Builder();
            // clone the user before making mods
            userBuilder.active(crowdUser.isActive());
            userBuilder.directoryId(crowdUser.getDirectoryId());
            userBuilder.displayName(crowdUser.getDisplayName());
            userBuilder.emailAddress(crowdUser.getEmailAddress());
            userBuilder.name(crowdUser.getName());

            if ((fullName != null) && !fullName.equals(
                crowdUser.getDisplayName())) {
                if (log.isDebugEnabled()) {
                    log.debug("updating user fullName to '" + fullName + "'");
                }

                userBuilder.displayName(fullName);
                updated = true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(
                        "new user fullName is same as old one: '" + fullName + "'");
                }
            }

            if ((emailAddress != null) && !emailAddress.equals(crowdUser.getEmailAddress())) {
                if (log.isDebugEnabled()) {
                    log.debug(
                        "updating user emailAddress to '" + emailAddress + "'");
                }

                userBuilder.emailAddress(emailAddress);
                updated = true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(
                        "new user emailAddress is same as old one: '" + emailAddress + "'");
                }
            }

            if (updated) {
                try {
                    crowdService.updateUser(userBuilder.toUser());
                } catch (Throwable t) {
                    log.error("Couldn't update user " + user.getName(),
                        t);
                }
            }
        }
    }

    //~--- get methods --------------------------------------------------------
    private String getLoggedInUser(HttpServletRequest request) {
        String remoteUser = null;

        if (config.getRemoteUserHeaderName()!=null) {

            // assumes it is first value in list, if header is defined multiple times. Otherwise would need to call getHeaders()
            String headerValue = request.getHeader(config.getRemoteUserHeaderName());

            // the Shibboleth SP sends multiple values as single value, separated by comma or semicolon
            List values = StringUtil.
                toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(headerValue);

            if (values != null && values.size() > 0) {

                // use the first in the list
                remoteUser = (String) values.get(0);

                if (log.isDebugEnabled()) {
                    log.debug("Got remoteUser '" + remoteUser + "' for header '" + config.
                        getRemoteUserHeaderName() + "'");
                }

                if (config.isConvertToUTF8()) {
                    String tmp = StringUtil.convertToUTF8(remoteUser);
                    if (tmp != null) {
                        remoteUser = tmp;
                        if (log.isDebugEnabled()) {
                            log.debug("remoteUser converted to UTF-8 '" + remoteUser + "' for header '" + config.
                                getRemoteUserHeaderName() + "'");
                        }
                    }
                }
            }

        }
        else {
            remoteUser = unwrapRequestIfNeeded(request).getRemoteUser();
        }

        return remoteUser;
    }

    // For SHBL-46 (Confluence 3.4.6 no longer wraps request- Thanks to Chad LaJoie for this fix!)
    private HttpServletRequest unwrapRequestIfNeeded(HttpServletRequest request) {
        if (request instanceof ServletRequestWrapper) {
            return (HttpServletRequest) ((ServletRequestWrapper) request).getRequest();
        }

        return request;
    }




    private String getEmailAddress(HttpServletRequest request) {
        String emailAddress = null;

        if (config.getEmailHeaderName()!=null) {

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
        }
        else {
            if (log.isDebugEnabled()) {
                log.debug("user email address header name in config was null/not specified");
            }
        }

        return emailAddress;
    }

    private String getFullName(HttpServletRequest request, String userid) {
        String fullName = null;

        if (config.getFullNameHeaderName()!=null) {

            // assumes it is first value in list, if header is defined multiple times. Otherwise would need to call getHeaders()
            String headerValue = request.getHeader(config.getFullNameHeaderName());

            // the Shibboleth SP sends multiple values as single value, separated by comma or semicolon
            List values = StringUtil.
                toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(headerValue);

            if (values != null && values.size() > 0) {

                if (log.isDebugEnabled()) {
                    log.debug("Original value of full name header '" + config.
                        getFullNameHeaderName() + "' was '" + headerValue + "'");
                }

                // use the first full name in the list
                //fullName = (String) values.get(1) + " " + (String) values.get(0);

                if (config.getFullNameMappings() == null || config.getFullNameMappings().size() == 0) {
                    // default if no fullname mappings is to just use the first header value
                    fullName = (String) values.get(0);
                }
                else {
                    fullName = createFullNameUsingMapping(headerValue, values);
                }

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
            else {
                if (log.isDebugEnabled()) {
                    log.debug("user full name header name in config was null/not specified");
                }
            }
        }

        if ((fullName == null) || (fullName.length() == 0)) {
            if (log.isDebugEnabled()) {
                log.debug("User full name was null or empty. Defaulting full name to user id");
            }

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

        // log headers (this is helpful to users for debugging what is sent in)
        if (log.isDebugEnabled()) {        	
            StringBuffer sb = new StringBuffer("HTTP Headers: ");
            boolean concat = false;
            for (Enumeration en = request.getHeaderNames(); en.hasMoreElements(); ) {
                if (concat) {
                    sb.append(", ");
                }
                String headerName = en.nextElement().toString();
                sb.append("'" + headerName
                          + "' = '" + request.getHeader(headerName) + "'");
                concat = true;
            }
            log.debug(sb.toString());
        }

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
                                    if(config.isOutputToLowerCase())
                                        result = result.toLowerCase();
                                    accumulatedRoles.add(result);

                                    log.debug("Found role mapping from '" +
                                        headerValue + "' to '" + result + "'");
                                }
                                found = true;
                            }
                        }
                    }

                    if (!found) {
                        log.debug(
                            "No mapper capable of processing role value=" + headerValue);
                    }
                }
            }
        }
    }


	// converting reliance on getUser(request,response) to use login() instead.
	// the logic flow:
	// 1) Seraph Login filter, which is based on username/password kicks in (declared at web.xml)
	// 2) it bails out altogether and identified user as invalid (without calling any of login(request,response) declared here
	// 3) Seraph Security filter kicks in (declared at web.xml)
	// 4) it calls getUser(request,response) and assign roles to known user
	// hence, getUser(request,response) will only be called from Seraph SecurityFilter
	
	// this pluggin uses ShibLoginFilter to make sure login is performed, however in the case ShibLoginFilter is
	// not configured, it will still work ;)
	

    /** 
     * @see com.atlassian.confluence.user.ConfluenceAuthenticator#login(
     *      javax.servlet.http.HttpServletRequest,
     *      javax.servlet.http.HttpServletResponse,
     *      java.lang.String username,
     *      java.lang.String password,
     *      boolean cookie)
     *
     * Check if user has been authenticated by Shib. Username, password, and cookie are totally ignored.
     */
    public boolean login(HttpServletRequest request, HttpServletResponse response, String username, String password, boolean cookie) throws AuthenticatorException{
 		
        if (log.isDebugEnabled()) {
            log.debug(
                "Request made to " + request.getRequestURL() + " triggered this AuthN check");
        }
       
        HttpSession httpSession = request.getSession();
        Principal user = null;

        // for those interested on the events
        String remoteIP = request.getRemoteAddr();
        String remoteHost = request.getRemoteHost();


        // Check if the user is already logged in
        if (httpSession.getAttribute(ConfluenceAuthenticator.LOGGED_IN_KEY) != null) {
			user = (Principal) httpSession.getAttribute(
				ConfluenceAuthenticator.LOGGED_IN_KEY);

            if (log.isDebugEnabled()) {
                log.debug(user.getName() + " already logged in, returning.");
            }
 
            return true;
        }

        // Since they aren't logged in, get the user name from
        // the REMOTE_USER header
        String userid = createSafeUserid(getLoggedInUser(request));

        if ((userid == null) || (userid.length() <= 0)) {
            if (log.isDebugEnabled()) {
                log.debug(
                    "Remote user was null or empty, calling super.login() to perform local login");
            }

            // Calling super.login to try local login if username and password are set
            // However, this won't work if ShibLoginFilter is used
            if (username != null && password != null) {
                if (log.isDebugEnabled())
                    log.debug("Trying local login for user "+username);
                
                return super.login(request, response, username, password, cookie);
            }
            else {
	            //SHBL-50 - login info table not being updated in Crowd
	            postLoginEvent();
            }
        }

        // Now that we know we will be trying to log the user in,
        // let's see if we should reload the config file first
        checkReloadConfig();

        // Convert username to all lowercase
        if (config.isUsernameConvertCase())
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
            } else if (config.isUpdateInfo()) {
                updateUser(user, fullName, emailAddress);
            }
        }

        if (config.isUpdateRoles() || newUser) {
            Set roles = new HashSet();

            //fill up the roles
            getRolesFromHeader(request, roles);

            assignUserToRoles(user, config.getDefaultRoles());
            assignUserToRoles(user, roles);

            //make sure we don't purge default roles either
            roles.addAll(config.getDefaultRoles());
            purgeUserRoles(user, roles);
        }

        // Now that we have the user's account, add it to the session and return
        if (log.isDebugEnabled()) {
            log.debug("Logging in user " + user.getName());
        }

        httpSession.setAttribute(
            ConfluenceAuthenticator.LOGGED_IN_KEY, user);
        httpSession.setAttribute(
            ConfluenceAuthenticator.LOGGED_OUT_KEY, null);
        
        getEventPublisher().publish(new LoginEvent(this, user.getName(), httpSession.getId(), remoteHost, remoteIP));

        return true;
	}
	
	// from Joseph Clark of Atlassian in https://answers.atlassian.com/questions/24227/invoke-embedded-crowd-login
	public void postLoginEvent() {
		// Fire the UserAuthenticatedEvent so that post-login processing is triggered ("copy-user-on-login", default group membership, group membership sync)
		final CrowdService crowdService = (CrowdService) ContainerManager.getComponent("crowdService");
		final CrowdDirectoryService directoryService = (CrowdDirectoryService) ContainerManager.getComponent("crowdDirectoryService");

		// Find the directory that the user belongs to.
		com.atlassian.crowd.embedded.api.User crowdUser = crowdService.getUser("TODO: get the username information from the incoming request");
		Directory directory = directoryService.findDirectoryById(crowdUser.getDirectoryId());
		if (!directory.getType().equals(DirectoryType.DELEGATING))
		{
		    // post-login processing only needs to be triggered on directories configured to use delegated LDAP Auth.
		    return;
		}

		// Obtain a reference to the ApplicationService and Application bean - needed in order to correctly construct the event.
		final ApplicationService applicationService = (ApplicationService) ContainerManager.getComponent("crowdApplicationService");
		final ApplicationDAO dao = (ApplicationDAO) ContainerManager.getComponent("embeddedCrowdApplicationDao");
		final Application application;
		try
		{
		    application = dao.findByName(EmbeddedCrowdBootstrap.APPLICATION_NAME);
		}
		catch (ApplicationNotFoundException e)
		{
		    // Do some error handling here; something is srsly wrong, for srs.
		    return;
		}

		// Fire the event.
		final EventPublisher eventPublisher = (EventPublisher) ContainerManager.getComponent("eventPublisher");
		eventPublisher.publish(new UserAuthenticatedEvent(applicationService, directory, application, (com.atlassian.crowd.model.user.User) crowdUser));
	}

    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {
        if (config.isUsingShibLoginFilter()) {
            return getUserForShibLoginFilter(request, response);
        }

        return getUserForAtlassianLoginFilter(request, response);
    }

    /**
     * Changes provided by colleague of Hans-Ulrich Pieper of Freie Universität Berlin *
     */
    public Principal getUserForAtlassianLoginFilter(HttpServletRequest request, HttpServletResponse response) {

        if (log.isDebugEnabled()) {
            log.debug(
                    "Request made to " + request.getRequestURL() + " triggered this AuthN check");
        }

        HttpSession httpSession = request.getSession();
        Principal user = null;

        // for those interested on the events
        String remoteIP = request.getRemoteAddr();
        String remoteHost = request.getRemoteHost();

        // Check if the user is already logged in
        if (httpSession.getAttribute(ConfluenceAuthenticator.LOGGED_IN_KEY) != null) {
            user = (Principal) httpSession.getAttribute(
                    ConfluenceAuthenticator.LOGGED_IN_KEY);

            if (log.isDebugEnabled()) {
                log.debug(user.getName() + " already logged in, returning.");
            }

            return user;
        }

        // Since they aren't logged in, get the user name from
        // the REMOTE_USER header
        String userid = createSafeUserid(getLoggedInUser(request));

        if ((userid == null) || (userid.length() <= 0)) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Remote user was null or empty, can not perform authentication");
            }
            getEventPublisher().publish(new LoginFailedEvent(this, "NoShibUsername", httpSession.getId(), remoteHost, remoteIP));

            return null;
        }

        // Now that we know we will be trying to log the user in,
        // let's see if we should reload the config file first
        checkReloadConfig();

        // Convert username to all lowercase
        if (config.isUsernameConvertCase())
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
            } else {
                // If user is still null, probably we're using an
                // external user database like LDAP. Either REMOTE_USER
                // isn't present there or is being filtered out, e.g.
                // by userSearchFilter
                if (log.isDebugEnabled()) {
                    log.debug(
                        "User does not exist and cannot create");
                }
                getEventPublisher().publish(new LoginFailedEvent(this, "CannotCreateUser", httpSession.getId(), remoteHost, remoteIP));

                return null;
            }
        } else {
            if (config.isUpdateInfo()) {
                updateUser(user, fullName, emailAddress);
            }
        }
        
        // TODO: All of this needs serious refactoring!
        // If config.isCreateUsers() == false, it would NPE later, so we
        // return null indicating that the login failed. Thanks to 
        // Adam Cohen for noticing this and to Bruce Liong for helping
        // to contribute a quick fix, modified by Gary Weaver. (SHBL-34)
        if (user == null) {
            if (log.isDebugEnabled()) {
                log.debug("Login attempt by '" + userid + "' failed.");
            }
            
            return null;
        }

        if (config.isUpdateRoles() || newUser) {
            Set roles = new HashSet();

            //fill up the roles
            getRolesFromHeader(request, roles);

            assignUserToRoles(user, config.getDefaultRoles());
            assignUserToRoles(user, roles);

            //make sure we don't purge default roles either
            roles.addAll(config.getDefaultRoles());
            purgeUserRoles(user, roles);
        }

        // Now that we have the user's account, add it to the session and return
        if (log.isDebugEnabled()) {
            log.debug("Logging in user " + user.getName());
        }

        httpSession.setAttribute(
                ConfluenceAuthenticator.LOGGED_IN_KEY, user);
        httpSession.setAttribute(
                ConfluenceAuthenticator.LOGGED_OUT_KEY, null);

        getEventPublisher().publish(new LoginEvent(this, user.getName(), httpSession.getId(), remoteHost, remoteIP));

        //return true;
        return user;
    }


    private String createSafeUserid(String originalRemoteuser){
        //possible to have multiple mappers defined, but
        //only 1 will produce the desired outcome
        Set possibleRemoteUsers = new HashSet();
        Collection mappers = config.getRemoteUserMappings();
        for (Iterator mapperIt = mappers.iterator(); mapperIt.hasNext();) {
            GroupMapper mapper = (GroupMapper) mapperIt.next();

            String[] results = (String[]) StringUtil.
                toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(
                mapper.process(originalRemoteuser)).toArray(new String[0]);

            if(results.length != 0)
                possibleRemoteUsers.addAll(Arrays.asList(results));
        }

        if(possibleRemoteUsers.isEmpty()){
            log.debug("Remote user is returned as is, mappers do not matched.");
            return originalRemoteuser;
        }

        if(log.isDebugEnabled() && possibleRemoteUsers.size() > 1){
            log.debug("Remote user has been transformed, but there are too many results, choosing one that seems suitable");
        }

        //just get a random one
        String output = possibleRemoteUsers.iterator().next().toString();
        return remoteUserCharsReplacement(output);
    }

    //if remoteuser.replace is specified, process it
    //it has the format of pair-wise value, occurences of 1st entry regex is replaced
    //with what specified on the second entry
    //the list is comma or semi-colon separated (which means
    //pretty obvious a comma or semi-colon can't be used in the content replacement)
    private String remoteUserCharsReplacement(String remoteUser){
        Iterator it = config.getRemoteUserReplacementChars();
        while(it.hasNext()){
            String replaceFromRegex = it.next().toString();

            //someone didn't fill up pair-wise entry, ignore this regex
            if(!it.hasNext()){
                if(replaceFromRegex.length() != 0)
                   log.debug("Character replacements specified for Remote User regex is incomplete, make sure the entries are pair-wise, skipping...");
                break;
            }

            String replacement = it.next().toString();
            
            //we are not going to replace empty string, so skip it
            if(replaceFromRegex.length()==0){
                log.debug("Empty string is found in Remote User replaceFrom regex, skipping...");
                continue;
            }

            try{
                remoteUser = remoteUser.replaceAll(replaceFromRegex, replacement);
            }catch(Exception e){
                log.warn("Fail to replace certain character entries in \"Remote User\" matching regex=\""+replaceFromRegex+"\", ignoring...");
                log.debug("Fail to replace certain character entries in Remote User",e);
            }
        }
        return remoteUser;
    }

    private String createFullNameUsingMapping(String originalFullNameHeaderValue, List values){
        //possible to have multiple mappers defined, but
        //only 1 will produce the desired outcome
        Set possibleFullNames = new HashSet();
        Collection mappers = config.getFullNameMappings();
        for (Iterator mapperIt = mappers.iterator(); mapperIt.hasNext();) {
            GroupMapper mapper = (GroupMapper) mapperIt.next();

            String[] results = (String[]) StringUtil.
                toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(
                mapper.process(originalFullNameHeaderValue)).toArray(new String[0]);

            if(results.length != 0)
                possibleFullNames.addAll(Arrays.asList(results));
        }

        if(possibleFullNames.isEmpty()){
            log.debug("Full Name header value is returned as is, mappers do not match, so will use first value in list.");
            return (String) values.get(0);
        }

        if(log.isDebugEnabled() && possibleFullNames.size() > 1){
            log.debug("Full name has been transformed, but there are too many results, choosing one that seems suitable");
        }

        //just get a random one
        String output = possibleFullNames.iterator().next().toString();
        return fullNameCharsReplacement(output);
    }

    //if fullname.replace is specified, process it
    //it has the format of pair-wise value, occurences of 1st entry regex is replaced
    //with what specified on the second entry
    //the list is comma or semi-colon separated (which means
    //pretty obvious a comma or semi-colon can't be used in the content replacement)
    private String fullNameCharsReplacement(String fullName){
        Iterator it = config.getFullNameReplacementChars();
        while(it.hasNext()){
            String replaceFromRegex = it.next().toString();

            //someone didn't fill up pair-wise entry, ignore this regex
            if(!it.hasNext()){
                if(replaceFromRegex.length() != 0)
                   log.debug("Character replacements specified for Full Name regex is incomplete, make sure the entries are pair-wise, skipping...");
                break;
            }

            String replacement = it.next().toString();

            //we are not going to replace empty string, so skip it
            if(replaceFromRegex.length()==0){
                log.debug("Empty string is found in Full Name replaceFrom regex, skipping...");
                continue;
            }

            try{
                fullName = fullName.replaceAll(replaceFromRegex, replacement);
            }catch(Exception e){
                log.warn("Fail to replace certain character entries in \"Remote User\" matching regex=\""+replaceFromRegex+"\", ignoring...");
                log.debug("Fail to replace certain character entries in Remote User",e);
            }
        }
        return fullName;
    }
	
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
    public Principal getUserForShibLoginFilter(HttpServletRequest request, HttpServletResponse response) {
        // If using ShibLoginFilter, see SHBL-24 - Authentication with local accounts should be supported
        if (log.isDebugEnabled()) {
            log.debug(
                "Request made to " + request.getRequestURL() + " triggered this AuthN2 check");
        }

        HttpSession httpSession = request.getSession(false);
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

		//worst case scenario, this is executed when user has not logged in previously
		//perhaps admin forgot to change web.xml to use ShibLoginFilter ?
		try{
			boolean authenticated = login(request,response,null,null,false);
			if (!authenticated) {
			    return null;
		    }
		}catch(Throwable t){
			log.error("Failed to authenticate user", t);
			return null;
		}
		return getUser(request,response);
    }

    public CrowdService getCrowdService() {
	    return (CrowdService)ContainerManager.getComponent("crowdService");
	}
	
	public GroupManager getGroupManager() {
	    return (GroupManager)ContainerManager.getComponent("groupManager");
	}
}
