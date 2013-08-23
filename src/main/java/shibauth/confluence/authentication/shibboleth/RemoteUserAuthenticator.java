/*
 Copyright (c) 2008-2013, Confluence HTTP Authenticator Team
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
 * Neither the name of the Confluence HTTP Authenticator Team
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
 * See source control logs and revision history for further detail of changes.
 * Modified 2009-09-29 call super.login() if REMOTE_USER wasn't set to enable local Confluence login (SHBL-24) [Juhani Gurney]
 * Modified 2009-01-22 to make use of ShibLoginFilter (SHBL-16), make updateLastLogin as optional [Bruc Liong]
 * Modified 2009-01-05 to revamp the mapping processing mechanism to handle regex, purging roles, etc (SHBL-6) [Bruc Liong]
 * Modified 2008-12-03 to encorporate patch from Vladimir Mencl for SHBL-8 related to CONF-12158 (DefaultUserAccessor checks permissions before adding membership in 2.7 and later)
 * Modified 2008-07-29 to fix UTF-8 encoding [Helsinki University], made UTF-8 fix optional [Duke University]
 * Modified 2008-01-07 to add role mapping from shibboleth attribute (role) to confluence group membership. [Macquarie University - MELCOE - MAMS], refactor config loading, constants, utility method, and added configuration VO [Duke University]
 * Modified 2007-05-21 additional checks/logging and some small refactoring. Changed to use UserAccessor so should work with Confluence 2.3+ [Duke University]
 * Original version by Georgetown University. Original version (v1.0) from: https://svn.middleware.georgetown.edu/confluence/remoteAuthn
 */

package shibauth.confluence.authentication.shibboleth;

import com.atlassian.confluence.event.events.security.LoginEvent;
import com.atlassian.confluence.event.events.security.LoginFailedEvent;
import com.atlassian.confluence.security.login.LoginManager;
import com.atlassian.confluence.user.ConfluenceAuthenticator;
import com.atlassian.confluence.user.UserAccessor;
import com.atlassian.crowd.embedded.api.CrowdService;
import com.atlassian.crowd.embedded.api.Group;
import com.atlassian.crowd.embedded.api.User;
import com.atlassian.crowd.embedded.impl.ImmutableUser;
import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.seraph.auth.LoginReason;
import com.atlassian.seraph.util.RedirectUtils;
import com.atlassian.spring.container.ContainerManager;
import com.atlassian.user.GroupManager;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.interceptor.DefaultTransactionAttribute;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

import javax.servlet.ServletRequestWrapper;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.security.Principal;
import java.util.*;

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
 * <p/>
 * <li><strong>username.convertcase</strong> - Indicates whether usernames
 * should be converted to lowercase before use</li>
 * <p/>
 * <li><strong>update.roles</strong> - Indicates whether the existing accounts
 * should have their roles updated based on the header information. note: old
 * roles are not removed if the header doesn't contain it. (Acceptable values:
 * true/false. Default to false)</li>
 * <p/>
 * <li><strong>dynamicroles.auto_create_role</strong> - should new roles be
 * automatically created in confluence (and users assigned to it). Default to false
 * <p/>
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

    private static final long serialVersionUID = -5608187140008286795L;
    private final static Log log = LogFactory.getLog(RemoteUserAuthenticator.class);
    private static ShibAuthConfiguration config;

    // Initialize properties from property file
    static {
        config = ShibAuthConfigLoader.getShibAuthConfiguration(null);
    }

    //public RemoteUserAuthenticator() {
        // SHBL-48/CONF-22266 - Authenticators in Confluence 3.5:
        // * Cannot have Atlassian beans injected via Spring (see comment late in CONF-22266)
        // * Authenticators must be classloaded and cannot be Atlassian plugins v1 or v2 (see comment late in
        // CONF-22266), so neither setter nor constructor injection of CrowdService instance would work.
        // * Can only get bean instances using ContainerManager after the beans have been constructed, so cannot be done
        // here in constructor.
    //}

    /**
     * Check if the configuration file should be reloaded and reload the configuration.
     */
    private void checkReloadConfig() {

        if (config.isReloadConfig() && (config.getConfigFile() != null)) {
            if (System.currentTimeMillis() < config.getConfigFileLastChecked() +
                    config.getReloadConfigCheckInterval()) {
                return;
            }

            long configFileLastModified = new File(config.getConfigFile()).lastModified();

            if (configFileLastModified != config.getConfigFileLastModified()) {
                if (log.isDebugEnabled()) {
                    log.debug("Config file has been changed, reloading");
                }

                config = ShibAuthConfigLoader.getShibAuthConfiguration(config);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Config file has not been changed, not reloading");
                }

                config.setConfigFileLastChecked(System.currentTimeMillis());
            }
        }
    }

    /**
     * Assigns a user to the roles.
     *
     * @param user the user to assign to the roles.
     */
    private void assignUserToRoles(User user, Collection roles, User crowdUser) {
        if (user == null) {
            if (log.isDebugEnabled()) {
                log.debug("User was null, not adding any roles...");
            }
        } else if (roles.size() == 0) {
            if (log.isDebugEnabled()) {
                log.debug("No roles specified, not adding any roles...");
            }
        } else {
            GroupManager groupManager = getGroupManager();
            if (groupManager == null) {
                throw new RuntimeException("groupManager was not wired in RemoteUserAuthenticator");
            }

            for (Iterator it = roles.iterator(); it.hasNext(); ) {
                String role = it.next().toString().trim();

                if (role.length() == 0) {
                    continue;
                }

                if (log.isDebugEnabled()) {
                    log.debug("Assigning " + user.getName() + " to role " + role);
                }

                Group group = getCrowdService().getGroup(role);
                if (group == null) {
                    if (config.isAutoCreateGroup()) {
                        try {
                            if (log.isDebugEnabled()) {
                                log.debug("Creating missing role '" + role + "'.");
                            }
                            groupManager.createGroup(role);
                            group = getCrowdService().getGroup(role);
                        } catch (Throwable t) {
                            log.error("Cannot create role '" + role + "'.", t);
                            continue;
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("Skipping autocreation of role '" + role + "'.");
                        }

                        continue; //no point of attempting to allocate user
                    }
                }

                if (crowdUser == null) {
                    log.warn("Could not find user '" + user.getName() + "' to add them to role '" + role + "'.");
                } else if (!crowdUser.isActive()) {
                    log.warn("User '" + user.getName() + "' was inactive, so did not add them to role '" + role + "'.");
                } else if (group == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Skipping " + user.getName() + " to role " + role + ", because crowdService.getGroup(\"" + role + "\") returned null.");
                    }
                } else if (getCrowdService().isUserMemberOfGroup(crowdUser, group)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Skipping " + user.getName() + " to role " + role + " - already a member");
                    }

                } else {
                    try {
                        addUserToGroup(crowdUser, group);
                    } catch (Throwable t) {
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
     * @param user        the user to assign to the roles.
     * @param rolesToKeep keep these roles, otherwise everything else
     *                    mentioned in the purgeMappings can go.
     */
    private void purgeUserRoles(User user, Collection rolesToKeep) {
        if ((config.getPurgeMappings().size() == 0)) {
            if (log.isDebugEnabled()) {
                log.debug("No roles to purge specified, not purging any roles...");
            }
        } else {
            UserAccessor userAccessor = getUserAccessor();
            if (userAccessor == null) {
                throw new RuntimeException("userAccessor was not wired in RemoteUserAuthenticator");
            }

            CrowdService crowdService = getCrowdService();
            if (crowdService == null) {
                throw new RuntimeException("crowdService was not wired in RemoteUserAuthenticator");
            }

            User crowdUser = crowdService.getUser(user.getName());
            Collection purgeMappers = config.getPurgeMappings();

            List<String> roles = userAccessor.getGroupNames(userAccessor.getUser(user.getName()));

            for (int i = 0; i < roles.size(); i++) {
                String role = roles.get(i);
                if (!StringUtil.containsStringIgnoreCase(rolesToKeep, role)) {
                    //run through the purgeMappers for this role
                    for (Iterator it2 = purgeMappers.iterator(); it2.hasNext(); ) {
                        GroupMapper mapper = (GroupMapper) it2.next();

                        String output = mapper.process(role);
                        if (output != null) {
                            try {
                                Group group = crowdService.getGroup(role);
                                if (crowdService.isUserMemberOfGroup(crowdUser, group)) {
                                    if (log.isDebugEnabled()) {
                                        log.debug("Removing user " + user.getName() + " from role " + role);
                                    }

                                    removeUserFromGroup(crowdService, crowdUser, group);

                                    // Only remove one group per login. Assuming this is to avoid massive delays in
                                    // login for a user removed from a lot of groups.
                                    break;
                                }
                            } catch (Throwable t) {
                                log.error("Error encountered in removing user " + user.getName() + " from role " + role,
                                        t);
                            }
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Keeping role " + role + " for user " + user.getName());
                    }
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
     * @param username user name for the new user
     * @return the new user
     */
    private void createUser(String username) {
        if (log.isInfoEnabled()) {
            log.info("Creating user account for " + username);
        }

        try {
            createUser(getUserAccessor(), username);
        } catch (Throwable t) {

            // Note: just catching EntityException like we used to do didn't
            // seem to cover Confluence massive with Oracle
            if (log.isDebugEnabled()) {
                log.debug("Error creating user " + username +
                        ". Will ignore and try to get the user (maybe it was already created)", t);
            }
        }
    }

    private void updateUser(User user, String fullName, String emailAddress) {
        // If we have new values for name or email, update the user object
        if (user == null) {
            if (log.isDebugEnabled()) {
                log.debug("User is null, so can't update it.");
            }
        } else {
            boolean updated = false;

            CrowdService crowdService = getCrowdService();
            if (crowdService == null) {
                throw new RuntimeException("crowdService was not wired in RemoteUserAuthenticator");
            }
            User crowdUser = crowdService.getUser(user.getName());
            ImmutableUser.Builder userBuilder = new ImmutableUser.Builder();
            // Have to clone the user before making mods.
            userBuilder.active(crowdUser.isActive());
            userBuilder.directoryId(crowdUser.getDirectoryId());
            userBuilder.displayName(crowdUser.getDisplayName());
            userBuilder.emailAddress(crowdUser.getEmailAddress());
            userBuilder.name(crowdUser.getName());

            if ((fullName != null) && !fullName.equals(crowdUser.getDisplayName())) {
                if (log.isDebugEnabled()) {
                    log.debug("Updating user fullName to '" + fullName + "'");
                }

                userBuilder.displayName(fullName);
                updated = true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("New user fullName is same as old one: '" + fullName + "'");
                }
            }

            if ((emailAddress != null) && !emailAddress.equals(crowdUser.getEmailAddress())) {
                if (log.isDebugEnabled()) {
                    log.debug("Updating user emailAddress to '" + emailAddress + "'");
                }

                userBuilder.emailAddress(emailAddress);
                updated = true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("New user emailAddress is same as old one: '" + emailAddress + "'");
                }
            }

            if (updated) {
                try {
                    updateUser(crowdService, userBuilder.toUser());
                } catch (Throwable t) {
                    log.error("Couldn't update user " + user.getName(), t);
                }
            }
        }
    }

    private String getLoggedInUser(HttpServletRequest request) {
        String remoteUser = null;

        if (config.getRemoteUserHeaderName() != null) {
            String headerValue = getAttribute(request, config.getRemoteUserHeaderName());
            // the Shibboleth SP sends multiple values as single value, separated by comma or semicolon
            List values = StringUtil.toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(headerValue);

            if (values != null && values.size() > 0) {
                // use the first in the list, if header is defined multiple times. Otherwise should call getHeaders().
                remoteUser = (String) values.get(0);

                if (log.isDebugEnabled()) {
                    log.debug("Got remoteUser '" + remoteUser + "' for header '" + config.getRemoteUserHeaderName() +
                            "'");
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

        } else {
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

        if (config.getEmailHeaderName() != null) {
            String headerValue = getAttribute(request, config.getEmailHeaderName());
            // The Shibboleth SP sends multiple values as single value, separated by comma or semicolon.
            List values = StringUtil.
                    toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(headerValue);

            if (values != null && values.size() > 0) {
                // Use the first email in the list.
                emailAddress = (String) values.get(0);

                if (log.isDebugEnabled()) {
                    log.debug("Got emailAddress '" + emailAddress + "' for header '" + config.getEmailHeaderName() +
                            "'");
                }

                if (config.isConvertToUTF8()) {
                    String tmp = StringUtil.convertToUTF8(emailAddress);
                    if (tmp != null) {
                        emailAddress = tmp;
                        if (log.isDebugEnabled()) {
                            log.debug("emailAddress converted to UTF-8 '" + emailAddress + "' for header '" +
                                    config.getEmailHeaderName() + "'");
                        }
                    }
                }
            }

            if ((emailAddress != null) && (emailAddress.length() > 0)) {
                emailAddress = emailAddress.toLowerCase();
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("User email address header name in config was null/not specified.");
            }
        }

        return emailAddress;
    }

    private String getFullName(HttpServletRequest request, String userid) {
        String fullName = null;

        if (config.getFullNameHeaderName() != null) {
            // assumes it is first value in list, if header is defined multiple times. Otherwise would need to call getHeaders()
            String headerValue = getAttribute(request, config.getFullNameHeaderName());
            // the Shibboleth SP sends multiple values as single value, separated by comma or semicolon
            List values = StringUtil.toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(headerValue);

            if (values != null && values.size() > 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Original value of full name header '" + config.getFullNameHeaderName() + "' was '" +
                            headerValue + "'");
                }

                if (config.getFullNameMappings() == null || config.getFullNameMappings().size() == 0) {
                    // Default is to just use the first header value, if no fullname mappings.
                    fullName = (String) values.get(0);
                } else {
                    fullName = createFullNameUsingMapping(headerValue, values);
                }

                if (log.isDebugEnabled()) {
                    log.debug("Got fullName '" + fullName + "' for header '" + config.getFullNameHeaderName() + "'.");
                }

                if (config.isConvertToUTF8()) {
                    String tmp = StringUtil.convertToUTF8(fullName);
                    if (tmp != null) {
                        fullName = tmp;
                        if (log.isDebugEnabled()) {
                            log.debug("fullName converted to UTF-8 '" + fullName + "' for header '" +
                                    config.getFullNameHeaderName() + "'.");
                        }
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("User full name header name in config was null/not specified.");
                }
            }
        }

        if ((fullName == null) || (fullName.length() == 0)) {
            if (log.isDebugEnabled()) {
                log.debug("User full name was null or empty. Defaulting full name to user id.");
            }

            fullName = userid;
        }

        return fullName;
    }

    /**
     * This will populate accumulated (containing all roles discovered).
     */
    private void getRolesFromHeader(HttpServletRequest request,
                                    Set accumulatedRoles) {
        Set attribHeaders = config.getGroupMappingKeys();

        // check if we're interested in headers
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
                sb.append("'" + headerName + "' = '" + request.getHeader(headerName) + "'");
                concat = true;
            }
            log.debug(sb.toString());
        }

        //process the headers by looking up only those list of registered headers
        for (Iterator headerIt = attribHeaders.iterator(); headerIt.hasNext(); ) {
            String headerName = headerIt.next().toString();

            String headerValuesString = null;

            Object attr = request.getAttribute(headerName);
            if (attr instanceof String) {
                headerValuesString = (String) attr;
            }

            if (headerValuesString == null) {
                headerValuesString = "";
                for (Enumeration en = request.getHeaders(headerName); en.hasMoreElements(); ) {
                    headerValuesString += en.nextElement().toString();
                }
            }

            //shib sends values in semicolon separated, so split it up too
            List headerValues = StringUtil.toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(headerValuesString);
            for (int j = 0; j < headerValues.size(); j++) {
                String headerValue = (String) headerValues.get(j);
                if (config.isConvertToUTF8()) {
                    String tmp = StringUtil.convertToUTF8(headerValue);
                    if (tmp != null) {
                        headerValue = tmp;
                    }
                }

                if (log.isDebugEnabled()) {
                    log.debug("Processing dynamicroles header=" + headerName + ", value=" + headerValue);
                }

                Collection mappers = config.getGroupMappings(headerName);
                boolean found = false;

                for (Iterator mapperIt = mappers.iterator(); mapperIt.hasNext(); ) {
                    GroupMapper mapper = (GroupMapper) mapperIt.next();

                    // We may get multiple groups returned by a single matched, e.g. matching "XXX" --> "A, B, C".
                    String[] results = (String[]) StringUtil.toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(
                            mapper.process(headerValue)).toArray(new String[0]);

                    for (int i = 0; i < results.length; i++) {
                        String result = results[i];

                        if (result.length() != 0) {
                            if (!accumulatedRoles.contains(result)) {
                                if (config.isOutputToLowerCase()) {
                                    result = result.toLowerCase();
                                }

                                accumulatedRoles.add(result);

                                if (log.isDebugEnabled()) {
                                    log.debug("Found role mapping from '" + headerValue + "' to '" + result + "'");
                                }
                            }
                            found = true;
                        }
                    }
                }

                if (log.isDebugEnabled() && !found) {
                    log.debug("No mapper capable of processing role value=" + headerValue);
                }
            }
        }
    }

    /**
     * @see com.atlassian.confluence.user.ConfluenceAuthenticator#login(
     *javax.servlet.http.HttpServletRequest,
     *      javax.servlet.http.HttpServletResponse,
     *      java.lang.String username,
     *      java.lang.String password,
     *      boolean cookie)
     *      <p/>
     *      Check if user has been authenticated by Shib. Username, password, and cookie are totally ignored.
     */
    public boolean login(HttpServletRequest request, HttpServletResponse response, String username, String password, boolean cookie) throws AuthenticatorException {

        // Converting reliance on getUser(request,response) to use login(...) instead. The logic flow is:
        // 1) Seraph Login filter, which is based on username/password kicks in (declared at web.xml)
        // 2) It bails out altogether and identified user as invalid (without calling any of login(request,response)
        //    declared here.
        // 3) Seraph Security filter kicks in (declared at web.xml)
        // 4) It calls getUser(request,response) and assign roles to known user.
        // Hence, getUser(request,response) will only be called from Seraph SecurityFilter. This authenticator can use
        // ShibLoginFilter to make sure login is performed in some versions of Confluence, but it works without it, so
        // that is off by default.

        String remoteIP = request.getRemoteAddr();
        String remoteHost = request.getRemoteHost();

        if (log.isDebugEnabled()) {
            log.debug("login(...) called. requestURL=" + request.getRequestURL() + ", username=" + username + ", remoteIP=" + remoteIP + ", remoteHost=" + remoteHost);
        }

        // Since they aren't logged in, get the user name from the configured header (e.g. REMOTE_USER).
        String userid = createSafeUserid(getLoggedInUser(request));

        // Does the user have a "Remember Me" cookie set?
        final Principal cookieUser = getUserFromCookie(request, response);
        if (cookieUser != null) {
            log.debug(String.format("Login for user %s succeeded via Remember Me cookie", cookieUser.getName()));
            return true;
        }

        // Is the incoming request flagged with Basic Auth credentials?
        if (RedirectUtils.isBasicAuthentication(request, getAuthType())) {
            final Principal basicAuthUser = getUserFromBasicAuthentication(request, response);
            if (basicAuthUser != null) {
				if (log.isDebugEnabled()) {
                    log.debug(String.format("Login for user %s succeeded via Basic Auth", basicAuthUser.getName()));
				}
                return true;
            }
        }

        if ((userid == null) || (userid.length() <= 0)) {
            if (log.isDebugEnabled()) {
                log.debug("Remote user was null or empty.");
            }

            // Calling super.login to try local login if username and password are set. Local login won't work if
            // ShibLoginFilter is used
            if (username != null && password != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Trying local login for user " + username);
                }

                boolean localLoginSuccess = super.login(request, response, username, password, cookie);
                if (localLoginSuccess) {
					User user = getCrowdUser(username, request, remoteHost, remoteIP);
                    loginSuccessful(request, response, username, user, remoteHost, remoteIP);
                }
                else {
                    loginFailed(request, username, remoteHost, remoteIP, "LocalUserLoginFailed");
                }

                if (log.isDebugEnabled()) {
                    log.debug("Authenticator is returning " + localLoginSuccess + " from call to public boolean login(HttpServletRequest request, HttpServletResponse response, String username, String password, boolean cookie)");
                }

                return localLoginSuccess;
            }
            else {
                if (log.isDebugEnabled()) {
                    log.debug("Cannot perform local login because username or password was not provided.");
                }

                loginFailed(request, username, remoteHost, remoteIP, "LocalUserLoginWithNoCredentials");

                if (log.isDebugEnabled()) {
                    log.debug("Authenticator is returning false from call to public boolean login(HttpServletRequest request, HttpServletResponse response, String username, String password, boolean cookie)");
                }

                return false;
            }
        }

        // Now that we know we will be trying to log the user in,
        // let's see if we should reload the config file first
        checkReloadConfig();

        // Convert username to all lowercase because of issues with case, at least in earlier versions of Confluence.
        if (config.isUsernameConvertCase()) {
            userid = convertUsername(userid);
        }

        User crowdUser = getCrowdUser(userid, request, remoteHost, remoteIP);

        // Pull name and address from headers
        String fullName = getFullName(request, userid);
        String emailAddress = getEmailAddress(request);

        // Try to get the user's account based on the user name
        Principal user = getUser(userid);
        boolean newUser = false;

        // User didn't exist or was problem getting it. we'll try to create it if we can, otherwise will try to get it
        // again.
        if (user == null) {
            if (config.isCreateUsers()) {
                createUser(userid);
    	        newUser = true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Configuration does NOT allow creation of new user accounts, authentication will fail for " +
                            username);
                }

                loginFailed(request, username, remoteHost, remoteIP, "CreateUserDisabled");

                if (log.isDebugEnabled()) {
                    log.debug("Authenticator is returning false from call to public boolean login(HttpServletRequest request, HttpServletResponse response, String username, String password, boolean cookie)");
                }
                return false;
            }

            user = getUser(userid);
            if (user != null) {
                // update the first time even if update not set, because we need to set full name and email
                updateUser(crowdUser, fullName, emailAddress);
            } else {
                // this could be a warning rather than debug, but in certain environments it might happen more often.
                if (log.isDebugEnabled()) {
                    log.debug("Got null user after creating user " + username + " so could not update it to set its fullname or email.");
                }
            }
        } else {
            if (config.isUpdateInfo()) {
                updateUser(crowdUser, fullName, emailAddress);
            }
        }

        if (config.isUpdateRoles() || newUser) {
            updateGroupMemberships(request, crowdUser);
        }

        // kick off login related methods
        loginSuccessful(request, response, userid, crowdUser, remoteHost, remoteIP);

        if (log.isDebugEnabled()) {
            log.debug("Authenticator is returning true from call to public boolean login(HttpServletRequest request, HttpServletResponse response, String username, String password, boolean cookie)");
        }

        return true;
    }

	private void loginSuccessful(HttpServletRequest request,
			HttpServletResponse response, String username, User user,
			String remoteHost, String remoteIP) {
		if (log.isDebugEnabled()) {
			log.debug("Logging in user "
					+ ((user != null) ? user.getName() : username)
					+ ". request=" + request + ", response=" + response
					+ ", username=" + username + ", user=" + user
					+ ((user != null) ? ", user.getName=" + user.getName():"" ) + ", remoteHost="
					+ remoteHost + ", remoteIP=" + remoteIP);
		}

		if (user != null) {
			// SHBL-50 - code provided by Joseph Clark and Erkki Aalto to do
			// postlogin updates.
			// Some of this will break eventually with new Confluence/Crowd
			// versions.
			putPrincipalInSessionContext(request, user);
		}
		// TODO: Joe Clark uses getElevatedSecurityGuard() vs.
		// getLoginManager(). Which should we use?
		// see:
		// https://bitbucket.org/jaysee00/example-confluence-sso-authenticator/src/381eb95ebc08/src/main/java/com/atlassian/confluence/seraph/example/ExampleSSOAuthenticator.java
		getLoginManager().onSuccessfulLoginAttempt(username, request);
		getEventPublisher().publish(
		new LoginEvent(this, username, request.getSession().getId(),
						remoteHost, remoteIP, LoginEvent.UNKNOWN));
		LoginReason.OK.stampRequestResponse(request, response);
	}

    private void loginFailed(HttpServletRequest request, String username, String remoteHost, String remoteIP, String reason) {
        if (log.isDebugEnabled()) {
            log.debug("Login failed for user " + username + ". request=" + request + ", username=" + username + ", remoteHost=" + remoteHost + ", remoteIP="+ remoteIP + ", reason=" + reason);
        }

        getLoginManager().onFailedLoginAttempt(username, request);
        getEventPublisher().publish(new LoginFailedEvent(this, reason, request.getSession().getId(),
                remoteHost, remoteIP));
    }

    private void updateGroupMemberships(HttpServletRequest request, User user) {
    	if (user == null) {
            if (log.isDebugEnabled()) {
                log.debug("User is null, so can't update group memberships.");
            }
        } else {
	    	Set roles = new HashSet();

	        // Add user to groups.
	        getRolesFromHeader(request, roles);
	        assignUserToRoles(user, config.getDefaultRoles(), user);
	        assignUserToRoles(user, roles, user);

	        // Make sure we don't purge default roles either
	        roles.addAll(config.getDefaultRoles());
	        purgeUserRoles(user, roles);
        }
    }

	private User getCrowdUser(String userid, HttpServletRequest request, String remoteHost, String remoteIP) {
		CrowdService crowdService = getCrowdService();
        if (crowdService == null) {
            loginFailed(request, userid, remoteHost, remoteIP, "AuthenticatorConfigFailure");
            if (log.isDebugEnabled()) {
                log.debug("Authenticator is throwing RuntimeException from call to public boolean login(HttpServletRequest request, HttpServletResponse response, String username, String password, boolean cookie)");
            }

            throw new RuntimeException("crowdService was not wired in RemoteUserAuthenticator");
        }

		// ensure user is active
        User crowdUser = crowdService.getUser(userid);
        if (crowdUser != null && !crowdUser.isActive()) {
            log.info("Login failed for user '" + userid + "', because user is set as inactive. remoteIP=" + remoteIP + " remoteHost=" + remoteHost);

            loginFailed(request, userid, remoteHost, remoteIP, "UserInactive");

            if (log.isDebugEnabled()) {
                log.debug("Authenticator is returning null from call to public Principal getUser(HttpServletRequest request, HttpServletResponse response)");
            }
            return null;
        }

		return crowdUser;
	}

    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {

        String remoteIP = request.getRemoteAddr();
        String remoteHost = request.getRemoteHost();

        if (log.isDebugEnabled()) {
            log.debug("getUser(...) called. requestURL=" + request.getRequestURL() + ", remoteIP=" + remoteIP + ", remoteHost=" + remoteHost);
        }

        // Does the user have a "Remember Me" cookie set?
        final Principal cookieUser = getUserFromCookie(request, response);
        if (cookieUser != null) {
            log.debug(String.format("Login for user %s succeeded via Remember Me cookie", cookieUser.getName()));
            return cookieUser;
        }

        // Is the incoming request flagged with Basic Auth credentials?
        if (RedirectUtils.isBasicAuthentication(request, getAuthType())) {
            final Principal basicAuthUser = getUserFromBasicAuthentication(request, response);
            if (basicAuthUser != null) {
				if (log.isDebugEnabled()) {
                    log.debug(String.format("Login for user %s succeeded via Basic Auth", basicAuthUser.getName()));
				}
                return basicAuthUser;
            }
        }

		// Since they aren't logged in, get the user name from
        // the REMOTE_USER header
        String userid = createSafeUserid(getLoggedInUser(request));

        if ((userid == null) || (userid.length() <= 0)) {
            if (log.isDebugEnabled()) {
                log.debug("Remote user was null or empty, can not perform authentication.");
            }

            loginFailed(request, userid, remoteHost, remoteIP, "NoUsername");

            if (log.isDebugEnabled()) {
                log.debug("Authenticator is returning null from call to public Principal getUser(HttpServletRequest request, HttpServletResponse response)");
            }
            return null;
        }

        // Now that we know we will be trying to log the user in,
        // let's see if we should reload the config file first
        checkReloadConfig();

        // Convert username to all lowercase
        if (config.isUsernameConvertCase()) {
            userid = convertUsername(userid);
        }

		// Pull name and address from headers
        String fullName = getFullName(request, userid);
        String emailAddress = getEmailAddress(request);

        // Try to get the user's account based on the user name
        Principal user = getUser(userid);

        boolean newUser = false;

        // User didn't exist or was problem getting it. we'll try to create it
        // if we can, otherwise will try to get it again.
        if (user == null) {
            if (config.isCreateUsers()) {
                createUser(userid);
                newUser = true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Configuration does NOT allow creation of new user accounts, authentication will fail for " +
                            userid + ". Login attempt by '" + userid + "' failed.");
                }

                loginFailed(request, userid, remoteHost, remoteIP, "CreateUserDisabled");

                if (log.isDebugEnabled()) {
                    log.debug("Authenticator is returning null from call to public Principal getUser(HttpServletRequest request, HttpServletResponse response)");
                }
                return null;
            }

            user = getUser(userid);
            User crowdUser = getCrowdUser(userid, request, remoteHost, remoteIP);
            if (crowdUser == null) {
                return null;
            }

            if (user != null) {
                // update the first time even if update not set, because we need to set full name and email
                updateUser(crowdUser, fullName, emailAddress);
            } else {
                // If user is still null, probably we're using an
                // external user database like LDAP. Either REMOTE_USER
                // isn't present there or is being filtered out, e.g.
                // by userSearchFilter
                if (log.isDebugEnabled()) {
                    log.debug("User does not exist and cannot create it. Login attempt by '" + userid + "' failed.");
                }

                loginFailed(request, userid, remoteHost, remoteIP, "CannotCreateUser");

                if (log.isDebugEnabled()) {
                    log.debug("Authenticator is returning null from call to public Principal getUser(HttpServletRequest request, HttpServletResponse response)");
                }
                return null;
            }
        } else {
            User crowdUser = getCrowdUser(userid, request, remoteHost, remoteIP);
            if (crowdUser == null) {
                return null;
            }
            if (config.isUpdateInfo()) {
                updateUser(crowdUser, fullName, emailAddress);
            }
        }

        User crowdUser = getCrowdUser(userid, request, remoteHost, remoteIP);
        if (config.isUpdateRoles() || newUser) {
            updateGroupMemberships(request, crowdUser);
        }

        loginSuccessful(request, response, user.getName(), crowdUser, remoteHost, remoteIP);

        if (log.isDebugEnabled()) {
            log.debug("Authenticator is returning " + user + " from call to public Principal getUser(HttpServletRequest request, HttpServletResponse response)");
        }

        return user;
    }

    private String createSafeUserid(String originalRemoteuser) {
        // Possible to have multiple mappers defined, but only 1 will produce the desired outcome.
        Set possibleRemoteUsers = new HashSet();
        Collection mappers = config.getRemoteUserMappings();

        for (Iterator mapperIt = mappers.iterator(); mapperIt.hasNext(); ) {
            GroupMapper mapper = (GroupMapper) mapperIt.next();

            String[] results = (String[]) StringUtil.toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(
                    mapper.process(originalRemoteuser)).toArray(new String[0]);

            if (results.length != 0) {
                possibleRemoteUsers.addAll(Arrays.asList(results));
            }
        }

        if (possibleRemoteUsers.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Remote user is returned as is, mappers do not matched.");
            }

            return originalRemoteuser;
        }

        if (log.isDebugEnabled() && possibleRemoteUsers.size() > 1) {
            log.debug("Remote user has been transformed, but there are too many results, choosing one that seems suitable");
        }

        // Try the next one.
        // TODO: Is this adequate?
        String output = possibleRemoteUsers.iterator().next().toString();
        return remoteUserCharsReplacement(output);
    }

    private String remoteUserCharsReplacement(String remoteUser) {
        // If remoteuser.replace is specified, process it. It has the format of pair-wise value, occurences of 1st entry
        // regex is replaced with what specified on the second entry. The list is comma or semi-colon separated (which
        // means it is pretty obvious a comma or semi-colon can't be used in the content replacement.
        Iterator it = config.getRemoteUserReplacementChars();

        while (it.hasNext()) {
            String replaceFromRegex = it.next().toString();

            // Someone didn't fill up pair-wise entry, ignore this regex.
            if (!it.hasNext()) {
                if (replaceFromRegex.length() != 0) {
                    if (log.isDebugEnabled()) {
                        log.debug("Character replacements specified for Remote User regex is incomplete, make sure the entries are pair-wise, skipping...");
                    }
                }
                break;
            }

            String replacement = it.next().toString();

            // We are not going to replace empty string, so skip it.
            if (replaceFromRegex.length() == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Empty string is found in Remote User replaceFrom regex, skipping...");
                }

                continue;
            }

            try {
                remoteUser = remoteUser.replaceAll(replaceFromRegex, replacement);
            } catch (Throwable t) {
                log.warn("Failed to replace certain character entries in \"Remote User\" matching regex=\"" + replaceFromRegex + "\", ignoring...");

                if (log.isDebugEnabled()) {
                    log.debug("Failed to replace certain character entries in Remote User", t);
                }
            }
        }
        return remoteUser;
    }

    private String createFullNameUsingMapping(String originalFullNameHeaderValue, List values) {
        // It is possible to have multiple mappers defined, but only one will produce the desired outcome.
        Set possibleFullNames = new HashSet();
        Collection mappers = config.getFullNameMappings();

        for (Iterator mapperIt = mappers.iterator(); mapperIt.hasNext(); ) {
            GroupMapper mapper = (GroupMapper) mapperIt.next();
            String[] results = (String[]) StringUtil.
                    toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(
                            mapper.process(originalFullNameHeaderValue)).toArray(new String[0]);

            if (results.length != 0) {
                possibleFullNames.addAll(Arrays.asList(results));
            }
        }

        if (possibleFullNames.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Full Name header value returned. Mappers do not match, so will use first value in list.");
            }

            return (String) values.get(0);
        }

        if (log.isDebugEnabled() && possibleFullNames.size() > 1) {
            log.debug("Full name has been transformed, but more than one result, so choosing one that seems suitable.");
        }

        //just get a random one
        String output = possibleFullNames.iterator().next().toString();
        return fullNameCharsReplacement(output);
    }

    private String fullNameCharsReplacement(String fullName) {
        // If fullname.replace is specified, process it. It has the format of pair-wise value, occurences of 1st entry
        // regex is replaced with what specified on the second entry. The list is comma or semi-colon separated (which
        // means it is pretty obvious a comma or semi-colon can't be used in the content replacement.
        Iterator it = config.getFullNameReplacementChars();

        while (it.hasNext()) {
            String replaceFromRegex = it.next().toString();

            // Someone didn't fill up pair-wise entry, ignore this regex.
            if (!it.hasNext()) {
                if (replaceFromRegex.length() != 0) {
                    if (log.isDebugEnabled()) {
                        log.debug("Character replacements specified for Full Name regex is incomplete, make sure the entries are pair-wise, skipping...");
                    }
                }

                break;
            }

            String replacement = it.next().toString();

            // We are not going to replace empty string, so skip it.
            if (replaceFromRegex.length() == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Empty string is found in Full Name replaceFrom regex, skipping...");
                }

                continue;
            }

            try {
                fullName = fullName.replaceAll(replaceFromRegex, replacement);
            } catch (Exception e) {
                log.warn("Fail to replace certain character entries in username matching regex=\"" + replaceFromRegex +
                        "\".");
                if (log.isDebugEnabled()) {
                    log.debug("Failed to replace certain character entries in Remote User", e);
                }
            }
        }

        return fullName;
    }

    // avoid "Write operations are not allowed in read-only mode" per Joseph Clark of Atlassian in
    // https://answers.atlassian.com/questions/25160/crowdservice-updateuser-causes-write-operations-are-not-allowed-in-read-only-mode
    // https://developer.atlassian.com/display/CONFDEV/Hibernate+Sessions+and+Transaction+Management+Guidelines
    private void addUserToGroup(final User crowdUser, final Group group) {
        if (crowdUser == null) {
            log.warn("Cannot add null user to group!");
        } else if (group == null) {
            log.warn("Cannot add user to null group!");
        } else {
            new TransactionTemplate(getTransactionManager(), new DefaultTransactionAttribute(TransactionDefinition.PROPAGATION_REQUIRED)).execute(new TransactionCallback() {
                public Object doInTransaction(TransactionStatus status) {
                    try {
                        getCrowdService().addUserToGroup(crowdUser, group);
                    } catch (Throwable t) {
                        log.error("Failed to add user " + crowdUser.getName() + " to group '" + group.getName() + "'!", t);
                    }
                    return null;
                }
            });
        }
    }

    // avoid "Write operations are not allowed in read-only mode" per Joseph Clark of Atlassian in
    // https://answers.atlassian.com/questions/25160/crowdservice-updateuser-causes-write-operations-are-not-allowed-in-read-only-mode
    // https://developer.atlassian.com/display/CONFDEV/Hibernate+Sessions+and+Transaction+Management+Guidelines
    private void removeUserFromGroup(final CrowdService crowdService, final User crowdUser, final Group group) {
        if (crowdUser == null) {
            log.warn("Cannot remove null user from group!");
        } else if (group == null) {
            log.warn("Cannot remove user from null group!");
        } else {
            new TransactionTemplate(getTransactionManager(), new DefaultTransactionAttribute(TransactionDefinition.PROPAGATION_REQUIRED)).execute(new TransactionCallback() {
                public Object doInTransaction(TransactionStatus status) {
                    try {
                        crowdService.removeUserFromGroup(crowdUser, group);
                    } catch (Throwable t) {
                        log.error("Failed to remove user " + crowdUser.getName() + " from group '" + group.getName() + "'!", t);
                    }
                    return null;
                }
            });
        }
    }

    // avoid "Write operations are not allowed in read-only mode" per Joseph Clark of Atlassian in
    // https://answers.atlassian.com/questions/25160/crowdservice-updateuser-causes-write-operations-are-not-allowed-in-read-only-mode
    // https://developer.atlassian.com/display/CONFDEV/Hibernate+Sessions+and+Transaction+Management+Guidelines
    private void createUser(final UserAccessor userAccessor, final String username) {
        if (username != null) {
            new TransactionTemplate(getTransactionManager(), new DefaultTransactionAttribute(TransactionDefinition.PROPAGATION_REQUIRED)).execute(new TransactionCallback() {
                public Object doInTransaction(TransactionStatus status) {
                    try {
                        userAccessor.createUser(username);
                    } catch (Throwable t) {
                        log.error("Failed to create user '" + username + "'!", t);
                    }
                    return null;
                }
            });
        } else {
            log.warn("Cannot add user with null username!");
        }
    }

    // avoid "Write operations are not allowed in read-only mode" per Joseph Clark of Atlassian in
    // https://answers.atlassian.com/questions/25160/crowdservice-updateuser-causes-write-operations-are-not-allowed-in-read-only-mode
    // https://developer.atlassian.com/display/CONFDEV/Hibernate+Sessions+and+Transaction+Management+Guidelines
    private void updateUser(final CrowdService crowdService, final User crowdUser) {
        if (crowdUser != null) {
            new TransactionTemplate(getTransactionManager(), new DefaultTransactionAttribute(TransactionDefinition.PROPAGATION_REQUIRED)).execute(new TransactionCallback() {
                public Object doInTransaction(TransactionStatus status) {
                    try {
                        crowdService.updateUser(crowdUser);
                    } catch (Throwable t) {
                        log.error("Failed to update user '" + crowdUser.getName() + "'!", t);
                    }
                    return null;
                }
            });
        } else {
            log.warn("Cannot update null user!");
        }
    }

    public String getAttribute(HttpServletRequest request, String attributeName) {
        String attributeValue = null;

        Object attr = request.getAttribute(attributeName);
        if (attr instanceof String)
            attributeValue = (String) attr;

        if (attributeValue == null)
            attributeValue = request.getHeader(attributeName);

        return attributeValue;
    }

    public CrowdService getCrowdService() {
        return (CrowdService) ContainerManager.getComponent("crowdService");
    }

    public UserAccessor getUserAccessor() {
        return (UserAccessor) ContainerManager.getComponent("userAccessor");
    }

    public LoginManager getLoginManager() {
        return (LoginManager) ContainerManager.getComponent("loginManager");
    }

    public PlatformTransactionManager getTransactionManager() {
        return (PlatformTransactionManager) ContainerManager.getComponent("transactionManager");
    }

    public GroupManager getGroupManager() {
        return (GroupManager) ContainerManager.getComponent("groupManager");
    }
}
