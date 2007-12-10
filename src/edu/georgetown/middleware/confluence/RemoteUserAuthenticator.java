/*
 * Modified 2007-05-21 from Georgetown version so it would strip @duke.edu
 * from user id and changed package to duke.
 * Copyright [2007] [Duke University]
 * modification of original edu.georgetown.middleware.confluence version:
 * Copyright [2006] [Georgetown University]
 * Original version can be found here: https://svn.middleware.georgetown.edu/confluence/remoteAuthn/
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Note: the original version of the Confluence 2.5+  modification was in duke package, not Georgetown
package edu.georgetown.middleware.confluence;

import com.atlassian.confluence.user.ConfluenceAuthenticator;
import com.atlassian.confluence.user.UserAccessor;
import com.atlassian.seraph.config.SecurityConfig;
import com.atlassian.spring.container.ContainerManager;
import com.atlassian.user.Group;
import com.atlassian.user.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.*;

/**
 * An authenticator that uses the REMOTE_USER header as proof of authentication.
 * <p/>
 * Configuration properties are looked for in <i>/remoteUserAuthenticator.properties</i> on the classpath. This file
 * may contain the following properties:
 * <ul>
 * <li><strong>create.users</strong> - Indicates whether accounts should be created for individuals the first they are
 * encountered (acceptable values: true/false)</li>
 * <li><strong>update.info</strong> - Indicates whether existing accounts should have their name and email address information
 * updated when the user logs in (acceptable values: true/false)</li>
 * <li><strong>default.roles</strong> - The default roles newly created accounts will be given (format: comma
 * seperated list)</li>
 * <li><strong>header.fullname</strong> - The name of the HTTP header that will carry the full name of the user</li>
 * <li><strong>header.email</strong> - The name of the HTTP header that will carry the email address for the user</li>
 * </ul>
 */
public class RemoteUserAuthenticator extends ConfluenceAuthenticator {

    /**
     * Serial version UID
     */
    private static final long serialVersionUID = -5608187140008286795L;

    /**
     * Logger
     */
    private final static Log log = LogFactory.getLog(RemoteUserAuthenticator.class);

    /**
     * Location of configuration file on classpath
     */
    private final static String PROPERTY_FILE = "/remoteUserAuthenticator.properties";

    private final static Properties CONFIG_PROPERTIES;

    /**
     * create.user init parameter name
     */
    private final static String CREATE_USERS = "create.users";

    /**
     * default.role init parameter name
     */
    private final static String DEFAULT_ROLES = "default.roles";

    /**
     * update.info init parameter name
     */
    private final static String UPDATE_INFO = "update.info";

    /**
     * Name of full name header property
     */
    private final static String FULLNAME_HEADER_NAME_PROPERTY = "header.fullname";

    /**
     * Name of email address header property
     */
    private final static String EMAIL_HEADER_NAME_PROPERTY = "header.email";

    /**
     * Whether to create accounts for new users or not (from PROPERTY_FILE. set in static block)
     */
    private static boolean createUsers;

    /**
     * Whether or not to update name/email info for previously created users (from PROPERTY_FILE. set in static block)
     */
    private static boolean updateInfo;

    /**
     * Default roles for newly created users (from PROPERTY_FILE. set in static block)
     */
    private static List defaultRoles;

    /**
     * HTTP Header name that contains a user's full name (from PROPERTY_FILE. set in static block)
     */
    private static String fullNameHeaderName;

    /**
     * HTTP Header name that contains a user's email address (from PROPERTY_FILE. set in static block)
     */
    private static String emailHeaderName;


    /**
     * Initialize properties
     */
    public void init(Map params, SecurityConfig config) {
        super.init(params, config);
    }

    private String convertUsername(String userid) {
        if (userid != null) {
            userid = userid.toLowerCase();
        }
        return userid;
    }

    private String getFullName(HttpServletRequest request, String userid) {
        String fullName = request.getHeader(fullNameHeaderName);
        log.debug("Got fullName '" + fullName + "' for header '" + fullNameHeaderName + "'");
        if (fullName == null || fullName.length() == 0) {
            fullName = userid;
        }
        return fullName;
    }

    private String getEmailAddress(HttpServletRequest request) {
        String emailAddress = request.getHeader(emailHeaderName);
        log.debug("Got emailAddress '" + emailAddress + "' for header '" + emailHeaderName + "'");
        if (emailAddress != null && emailAddress.length() > 0) {
            emailAddress = emailAddress.toLowerCase();
        }
        return emailAddress;
    }

    // Tried overriding login(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse), but
    // it doesn't get called at all. That sucks because this method can often be called > 20 times per page.
    /*
     * @see com.atlassian.seraph.auth.Authenticator#getUser(javax.servlet.http.HttpServletRequest,
     *      javax.servlet.http.HttpServletResponse)
     */
    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {

        if (log.isDebugEnabled()) {
            log.debug("Request made to " + request.getRequestURL() + " triggered this AuthN check");
        }

        UserAccessor userAccessor = (UserAccessor) ContainerManager.getComponent("userAccessor");
        HttpSession httpSession = request.getSession();
        Principal user;

        // Check if the user is already logged in
        if (httpSession != null && httpSession.getAttribute(ConfluenceAuthenticator.LOGGED_IN_KEY) != null) {
            user = (Principal) httpSession.getAttribute(ConfluenceAuthenticator.LOGGED_IN_KEY);
            if (log.isDebugEnabled()) {
                log.debug("" + user.getName() + " already logged in, returning.");
            }
            return user;
        }

        // Since they aren't logged in, get the user name from the REMOTE_USER header
        String userid = request.getRemoteUser();
        if (userid == null || userid.length() <= 0) {
            if (log.isDebugEnabled()) {
                log.debug("Remote user was null or empty, can not perform authentication");
            }
            return null;
        }

        // Convert username to all lowercase
        userid = convertUsername(userid);

        // Pull name and address from headers
        String fullName = getFullName(request, userid);
        String emailAddress = getEmailAddress(request);

        // Try to get the user's account based on the user name
        user = getUser(userid);

        // User didn't exist or was problem getting it. we'll try to create it if we can, otherwise will try to get it again.
        if (user == null) {
            user = createUser(userAccessor, userid);

            if (user != null) {
                assignUserToRoles(userAccessor, (User) user);
                updateUser(userAccessor, user, fullName, emailAddress);
            }

        } else if (updateInfo) {
            updateUser(userAccessor, user, fullName, emailAddress);
        }

        // Now that we have the user's account, add it to the session and return
        if (log.isDebugEnabled()) {
            log.debug("Logging in user " + user.getName());
        }
        request.getSession().setAttribute(ConfluenceAuthenticator.LOGGED_IN_KEY, user);
        request.getSession().setAttribute(ConfluenceAuthenticator.LOGGED_OUT_KEY, null);
        return user;
    }

    private void updateUser(UserAccessor userAccessor, Principal user, String fullName, String emailAddress) {
        // If we have new values for name or email, update the user object
        if (user != null && user instanceof User) {

            User userToUpdate = (User) user;

            boolean updated = false;
            if (fullName != null && !fullName.equals(userToUpdate.getFullName())) {
                if (log.isDebugEnabled()) {
                    log.debug("updating user fullName to '" + fullName + "'");
                }
                userToUpdate.setFullName(fullName);
                updated = true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("new user fullName is same as old one: '" + fullName + "'");
                }
            }

            if (emailAddress != null && !emailAddress.equals(userToUpdate.getEmail())) {
                if (log.isDebugEnabled()) {
                    log.debug("updating user emailAddress to '" + emailAddress + "'");
                }
                userToUpdate.setEmail(emailAddress);
                updated = true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("new user emailAddress is same as old one: '" + emailAddress + "'");
                }
            }

            if (updated) {
                try {
                    userAccessor.saveUser(userToUpdate);
                }
                catch (Throwable t) {
                    log.error("Couldn't update user " + userToUpdate.getName(), t);
                }
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    public Principal getUser(UserAccessor userAccessor, String userid) {
        if (log.isDebugEnabled()) {
            log.debug("Getting user " + userid);
        }

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
     * Creates a new user if the configuration allows it.
     *
     * @param userid user name for the new user
     * @return the new user
     */
    private Principal createUser(UserAccessor userAccessor, String userid) {
        Principal user = null;
        if (createUsers) {
            if (log.isInfoEnabled()) {
                log.info("Creating user account for " + userid);
            }

            try {
                user = userAccessor.createUser(userid);
            } catch (Throwable t) {

                // Note: just catching EntityException like we used to do didn't seem to cover Confluence massive with Oracle
                if (log.isDebugEnabled()) {
                    log.debug("Error creating user " + userid + ". Will ignore and try to get the user (maybe it was already created)", t);
                }

                user = getUser(userAccessor, userid);

                if (user == null) {
                    log.error("Error creating user " + userid + ". Got null user after attempted to create user (so it probably was not a duplicate).", t);
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Configuration does NOT allow for creation of new user accounts, authentication will fail for "
                        + userid);
            }
        }

        return user;
    }

    /**
     * Assigns a user to the default roles.
     *
     * @param user the use to assign to the roles.
     */
    private void assignUserToRoles(UserAccessor userAccessor, User user) {
        if (defaultRoles.size() > 0) {

            if (log.isDebugEnabled()) {
                log.debug("Assigning default roles to user " + user.getName());
            }
            String role;
            Group group;

            for (int i = 0; i < defaultRoles.size(); i++) {
                role = (String) defaultRoles.get(i);

                if (log.isDebugEnabled()) {
                    log.debug("Assigning " + user.getName() + " to default role " + role);
                }
                try {
                    group = userAccessor.getGroup(role);
                    userAccessor.addMembership(group, user);
                } catch (Throwable e) {
                    log.error("Attempted to add user " + user + " to role " + role + " but the role does not exist, or got some other error.", e);
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("Default roles assigned to new user");
            }
        }
    }

    /**
     * Initialize properties from property file
     */
    static {
        if (log.isDebugEnabled()) {
            log.debug("Initializing authenticator using property file " + PROPERTY_FILE);
        }

        InputStream propsIn = RemoteUserAuthenticator.class.getResourceAsStream(PROPERTY_FILE);
        CONFIG_PROPERTIES = new Properties();
        try {
            CONFIG_PROPERTIES.load(propsIn);

            // Load create users property
            createUsers = Boolean.valueOf(CONFIG_PROPERTIES.getProperty(CREATE_USERS)).booleanValue();
            if (log.isDebugEnabled()) {
                log.debug("Setting create new users to " + createUsers);
            }

            // Load udpate info property
            updateInfo = Boolean.valueOf(CONFIG_PROPERTIES.getProperty(UPDATE_INFO)).booleanValue();
            if (log.isDebugEnabled()) {
                log.debug("Setting update user information to " + updateInfo);
            }

            // Load default roles
            defaultRoles = new ArrayList();
            String roles = CONFIG_PROPERTIES.getProperty(DEFAULT_ROLES);
            if (roles != null) {
                roles = roles.trim();
                StringTokenizer tokenizer = new StringTokenizer(roles, ",");
                String role;
                while (tokenizer.hasMoreTokens()) {
                    role = tokenizer.nextToken().trim();
                    if (log.isDebugEnabled()) {
                        log.debug("Adding role " + role + " to list of default user roles");
                    }
                    defaultRoles.add(role);
                }
            }

            fullNameHeaderName = CONFIG_PROPERTIES.getProperty(FULLNAME_HEADER_NAME_PROPERTY);
            if (log.isDebugEnabled()) {
                log.debug("HTTP Header that may contain user's full name set to: " + fullNameHeaderName);
            }

            emailHeaderName = CONFIG_PROPERTIES.getProperty(EMAIL_HEADER_NAME_PROPERTY);
            if (log.isDebugEnabled()) {
                log.debug("HTTP Header that may contain user's email address set to: " + emailHeaderName);
            }
        } catch (IOException e) {
            log.warn("Unable to read properties file, using default properties", e);
        }
    }
}
