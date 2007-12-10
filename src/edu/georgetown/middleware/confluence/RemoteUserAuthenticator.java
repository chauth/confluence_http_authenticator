/*
 * Copyright [2006] [Georgetown University]
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

package edu.georgetown.middleware.confluence;

import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;

import bucket.container.ContainerManager;

import com.atlassian.seraph.auth.DefaultAuthenticator;
import com.atlassian.seraph.config.SecurityConfig;
import com.atlassian.user.EntityException;
import com.atlassian.user.Group;
import com.atlassian.user.GroupManager;
import com.atlassian.user.User;
import com.atlassian.user.UserManager;

/**
 * An authenticator that uses the REMOTE_USER header as proof of authentication.
 * 
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
public class RemoteUserAuthenticator extends DefaultAuthenticator {

    /** Serial version UID */
    private static final long serialVersionUID = -5608187140008286795L;

    /** Logger */
    private final static Logger log = Logger.getLogger(RemoteUserAuthenticator.class);

    /** Location of configuration file on classpath */
    private final static String PROPERTY_FILE = "/remoteUserAuthenticator.properties";
    
    private final static Properties CONFIG_PROPERTIES;

    /** create.user init parameter name */
    private final static String CREATE_USERS = "create.users";

    /** default.role init parameter name */
    private final static String DEFAULT_ROLES = "default.roles";
    
    /** update.info init parameter name */
    private final static String UPDATE_INFO = "update.info";

    /** Name of full name header property */
    private final static String FULLNAME_HEADER_NAME_PROPERTY = "header.fullname";

    /** Name of email address header property */
    private final static String EMAIL_HEADER_NAME_PROPERTY = "header.email";

    /** Whether to create accounts for new users or not */
    private static boolean createUsers;
    
    /** Whether or not to update name/email info for previously created users */
    private static boolean updateInfo;

    /** Default roles for newly created users */
    private static List defaultRoles;
    
    /** HTTP Header name that contains a user's full name */
    private static String fullNameHeaderName;

    /** HTTP Header name that contains a user's email address */
    private static String emailHeaderName;

    /**
     * Initialize properties
     */
    public void init(Map params, SecurityConfig config) {
        super.init(params, config);
    }

    /*
     * @see com.atlassian.seraph.auth.Authenticator#getUser(javax.servlet.http.HttpServletRequest,
     *      javax.servlet.http.HttpServletResponse)
     */
    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {
        if (log.isDebugEnabled()) {
            log.debug("Request made to " + request.getRequestURL() + " triggered this AuthN check");
        }

        HttpSession httpSession = request.getSession();
        Principal user;

        // Check if the user is already logged in
        if (httpSession != null && httpSession.getAttribute(DefaultAuthenticator.LOGGED_IN_KEY) != null) {
            user = (Principal) httpSession.getAttribute(DefaultAuthenticator.LOGGED_IN_KEY);
            if (log.isDebugEnabled()) {
                log.debug(user.getName() + " already logged in, returning.");
            }
            return user;
        }

        // Since they aren't logged in, get the user name from the REMOTE_USER header
        String userid = request.getRemoteUser();
        if (userid == null || userid.length() <= 0) {
            log.debug("Remote user was null or empty, can not perform authentication");
            return null;
        }
        userid = userid.toLowerCase();

        // Try to get the user's account based on the user name
        if (log.isDebugEnabled()) {
            log.debug("Getting principal for user " + userid);
        }
        user = getUser(userid);

        // Pull name and address from headers
        String fullName = request.getHeader(fullNameHeaderName);
        if(fullName == null || fullName.length() == 0){
            fullName = userid;
        }
        
        String emailAddress = request.getHeader(emailHeaderName);
        if(emailAddress != null && emailAddress.length() > 0){
            emailAddress = emailAddress.toLowerCase();
        }
        
        // User didn't exist, lets create it if we can
        if (user == null) {
            if (log.isDebugEnabled()) {
                log.debug("No user account exists for " + userid);
            }
            
            user = createUser(userid, fullName, emailAddress);
        
        } else if (updateInfo) {
            // If we have new values for name or email, update the user object
            if (user instanceof User) {
                if (fullName != null && !fullName.equals((((User)user).getFullName()))) {
                    ((User)user).setFullName(fullName);
                }
                if (emailAddress != null && emailAddress.equals((((User)user).getEmail()))) {
                    ((User)user).setEmail(emailAddress);
                }
            }
        }

        // Now that we have the user's account, add it to the session and return
        if (log.isDebugEnabled()) {
            log.debug("Logging in user " + user.getName());
        }
        request.getSession().setAttribute(DefaultAuthenticator.LOGGED_IN_KEY, user);
        request.getSession().setAttribute(DefaultAuthenticator.LOGGED_OUT_KEY, null);
        return user;
    }

    /**
     * {@inheritDoc}
     */
    public Principal getUser(String userid) {
        try {
            UserManager userManager = (UserManager) ContainerManager.getComponent("userManager");

            if (log.isDebugEnabled()) {
                log.debug("Getting principal for user " + userid);
            }
            return userManager.getUser(userid);
        } catch (EntityException e) {
            log.error("Error encountered trying to fetch user information", e);
        }

        return null;
    }

    /**
     * Creates a new user if the configuration allows it.
     * 
     * @param userid user name for the new user
     * 
     * @return the new user
     */
    private User createUser(String userid, String fullName, String emailAddress) {
        UserManager userManager = (UserManager) ContainerManager.getComponent("userManager");
        User user = null;
        try {
            if (createUsers) {
                if (log.isInfoEnabled()) {
                    log.info("Configuration allows for creation of new user accounts, creating account for " + userid);
                }
                user = userManager.createUser(userid);

                if(fullName != null && fullName.length() > 0){
                    if (log.isDebugEnabled()) {
                        log.debug("Setting user's full name to " + fullName);
                    }
                    user.setFullName(fullName);
                }

                if(emailAddress != null && emailAddress.length() > 0){
                    if (log.isDebugEnabled()) {
                        log.debug("Setting user's email address to " + emailAddress);
                    }
                    user.setEmail(emailAddress);
                }

                if (log.isDebugEnabled()) {
                    log.debug("User record created.");
                }
                assignUserToRoles(user);
            } else {
                if (log.isDebugEnabled()) {
                    log
                            .debug("Configuration does NOT allow for creation of new user accounts, authentication will fail for "
                                    + userid);
                }
            }
        } catch (EntityException e) {
            log.error("Attempted to create user " + userid + " but a user by that name already exist.");
        }

        return user;
    }

    /**
     * Assigns a user to the default roles.
     * 
     * @param user the use to assign to the roles.
     */
    private void assignUserToRoles(User user) {
        if (defaultRoles.size() > 0) {

            if (log.isDebugEnabled()) {
                log.debug("Assigning default roles to user " + user.getName());
            }
            String role;
            Group group;

            GroupManager groupManager = (GroupManager) ContainerManager.getComponent("groupManager");

            for (int i = 0; i < defaultRoles.size(); i++) {
                role = (String) defaultRoles.get(i);

                if (log.isDebugEnabled()) {
                    log.debug("Assigning " + user.getName() + " to default role " + role);
                }
                try {
                    group = groupManager.getGroup(role);
                    groupManager.addMembership(group, user);
                } catch (EntityException e) {
                    log.error("Attempted to add user " + user + " to role " + role + " but the role does not exist.");
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