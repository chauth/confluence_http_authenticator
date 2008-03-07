/*
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

package shibauth.confluence.authentication.shibboleth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;


public class ShibAuthConfigLoader {

    private final static Log log =
        LogFactory.getLog(ShibAuthConfigLoader.class);

    public static ShibAuthConfiguration getShibAuthConfiguration() {
        if (log.isDebugEnabled()) {
            log.debug("Initializing authenticator using property file "
                      + ShibAuthConstants.PROPERTIES_FILE);
        }

        InputStream propsIn =
            RemoteUserAuthenticator.class.getResourceAsStream(ShibAuthConstants.PROPERTIES_FILE);

        ShibAuthConfiguration config = new ShibAuthConfiguration();

        try {
            Properties configProps = new Properties();
            configProps.load(propsIn);

            // Load create users property
            config.setCreateUsers( Boolean.valueOf(
                configProps.getProperty(ShibAuthConstants.CREATE_USERS)).booleanValue());

            if (log.isDebugEnabled()) {
                log.debug("Setting create new users to " + config.isCreateUsers());
            }

            // Load udpate info property
            config.setUpdateInfo( Boolean.valueOf(
                configProps.getProperty(ShibAuthConstants.UPDATE_INFO)).booleanValue());

            if (log.isDebugEnabled()) {
                log.debug("Setting update user information to " + config.isUpdateInfo());
            }

            // Load update role property
            config.setUpdateRoles( Boolean.valueOf(
                configProps.getProperty(ShibAuthConstants.UPDATE_ROLES)).booleanValue());

            if (log.isDebugEnabled()) {
                log.debug("Setting update user roles to " + config.isUpdateRoles());
            }

            // Load default roles
            List defaultRoles = new ArrayList();

            String roles = configProps.getProperty(ShibAuthConstants.DEFAULT_ROLES);

            if (roles != null) {

                defaultRoles.addAll(StringUtil.toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(roles));

                if (log.isDebugEnabled()) {
                    for (Iterator it =
                            defaultRoles.iterator(); it.hasNext(); ) {
                        log.debug("Adding role " + it.next().toString()
                                  + " to list of default user roles");
                    }
                }
            }

            config.setDefaultRoles(defaultRoles);

            config.setFullNameHeaderName(configProps.getProperty(ShibAuthConstants.FULLNAME_HEADER_NAME_PROPERTY));

            if (log.isDebugEnabled()) {
                log.debug(
                    "HTTP Header that may contain user's full name set to: "
                    + config.getFullNameHeaderName());
            }

            config.setEmailHeaderName(configProps.getProperty(ShibAuthConstants.EMAIL_HEADER_NAME_PROPERTY));

            if (log.isDebugEnabled()) {
                log.debug(
                    "HTTP Header that may contain user's email address set to: "
                    + config.getEmailHeaderName());
            }

            // fill in the header names to be monitored
            Set attribHeaders = new HashSet();

            // Load dynamic roles property
            String attribNameStr =
                configProps.getProperty(ShibAuthConstants.ROLES_ATTRIB_NAMES);

            if (attribNameStr != null) {
                List attribNames = StringUtil.toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(attribNameStr);

                if (log.isDebugEnabled()) {
                    for (Iterator it = attribNames.iterator(); it.hasNext(); ) {

                        // According to Bruc Liong, this is case-insensitive to make it easier on the admin.

                        String lowercaseAttrib =
                            it.next().toString().trim().toLowerCase();

                        log.debug("Reading dynamic attribute: " + lowercaseAttrib);
                        attribHeaders.add(lowercaseAttrib);
                    }
                }
            }

            config.setAttribHeaders(attribHeaders);

            Map mapRole = new HashMap();
            // remember the map from incoming attribute to confluence's group
            for (Enumeration propEnum = configProps.propertyNames();
                    propEnum.hasMoreElements(); ) {
                String prop = propEnum.nextElement().toString();

                // register as lower case in the map (dont think there would be
                // conflict between upper/lower cases
                String shibAttribFromConfig = prop.trim().toLowerCase();

                if (shibAttribFromConfig.startsWith(ShibAuthConstants.ROLES_ATTRIB_PREFIX)
                        &&!shibAttribFromConfig.startsWith(
                            ShibAuthConstants.ROLES_ATTRIB_NAMES)) {
                    String roleStr = configProps.getProperty(prop);
                    String roleKey = shibAttribFromConfig.substring(ShibAuthConstants.ROLES_ATTRIB_PREFIX.length());

                    //this is the map from shib_key = conf_group1, group2, etc
                    mapRole.put(roleKey,
                                StringUtil.toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(roleStr));

                    if (log.isDebugEnabled()) {
                        log.debug("Found role mapping declared as " + prop);
                    }
                }
            }

            config.setMapRole(mapRole);

        } catch (IOException e) {
            log.warn(
                "Unable to read properties file, using default properties", e);
        }

        return config;
    }
}
