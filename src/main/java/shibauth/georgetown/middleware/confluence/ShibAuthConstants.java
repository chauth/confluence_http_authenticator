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

package edu.georgetown.middleware.confluence;


public class ShibAuthConstants {
    
    /**
     * Location of configuration file on classpath
     */
    public final static String PROPERTIES_FILE =
        "/remoteUserAuthenticator.properties";

    /**
     * create.user init parameter name
     */
    public final static String CREATE_USERS = "create.users";

    /**
     * default.role init parameter name
     */
    public final static String DEFAULT_ROLES = "default.roles";

    /**
     * Name of email address header property
     */
    public final static String EMAIL_HEADER_NAME_PROPERTY = "header.email";

    /**
     * Name of full name header property
     */
    public final static String FULLNAME_HEADER_NAME_PROPERTY =
        "header.fullname";

    /**
     * Name of list of attributes (separated by comma or semicolon) in the
     * header as indication of dynamic roles to be used
     */
    public final static String ROLES_ATTRIB_NAMES =
        "header.dynamicroles.attributenames";

    /**
     * Prefix to be used for mapping of different roles. i.e.
     * header.dynamicroles.fromvalue=toRoleValue
     */
    public final static String ROLES_ATTRIB_PREFIX = "header.dynamicroles.";

    /**
     * update.info init parameter name
     */
    public final static String UPDATE_INFO = "update.info";

    /** update.roles init parameter name */
    public final static String UPDATE_ROLES = "update.roles";

}
