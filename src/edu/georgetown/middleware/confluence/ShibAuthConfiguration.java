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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;


public class ShibAuthConfiguration {

    /**
     * Set of header names to be watchfull for dynamic roles
     */
    private Set attribHeaders;

    /**
     * Whether to create accounts for new users or not
     */
    private boolean createUsers;

    /**
     * Default roles for newly created users
     */
    private List defaultRoles;

    /**
     * HTTP Header name that contains a user's email address
     */
    private String emailHeaderName;

    /**
     * HTTP Header name that contains a user's full name
     */
    private String fullNameHeaderName;

    /**
     * Mapping of a value of one of the 
     */
    private Map mapRole = new HashMap(10);

    /**
     * Whether or not to update name/email info for previously created users
     */
    private static boolean updateInfo;

    /**
     * Whether to update roles for new users or not
     */
    private static boolean updateRoles;

    public Set getAttribHeaders() {
        return attribHeaders;
    }

    public void setAttribHeaders(Set attribHeaders) {
        this.attribHeaders = attribHeaders;
    }

    public boolean isCreateUsers() {
        return createUsers;
    }

    public void setCreateUsers(boolean createUsers) {
        this.createUsers = createUsers;
    }

    public List getDefaultRoles() {
        return defaultRoles;
    }

    public void setDefaultRoles(List defaultRoles) {
        this.defaultRoles = defaultRoles;
    }

    public String getEmailHeaderName() {
        return emailHeaderName;
    }

    public void setEmailHeaderName(String emailHeaderName) {
        this.emailHeaderName = emailHeaderName;
    }

    public String getFullNameHeaderName() {
        return fullNameHeaderName;
    }

    public void setFullNameHeaderName(String fullNameHeaderName) {
        this.fullNameHeaderName = fullNameHeaderName;
    }

    public Map getMapRole() {
        return mapRole;
    }

    public void setMapRole(Map mapRole) {
        this.mapRole = mapRole;
    }

    public static boolean isUpdateInfo() {
        return updateInfo;
    }

    public static void setUpdateInfo(boolean updateInfo) {
        ShibAuthConfiguration.updateInfo = updateInfo;
    }

    public static boolean isUpdateRoles() {
        return updateRoles;
    }

    public static void setUpdateRoles(boolean updateRoles) {
        ShibAuthConfiguration.updateRoles = updateRoles;
    }
}
