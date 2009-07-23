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

package shibauth.confluence.authentication.shibboleth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ShibAuthConfiguration {

    /**
     * Collection of mappers capable of transforming remote-user into
     * something meaningful for confluence.
     */
    private Collection remoteUserMappings = new ArrayList();

    /** Contains lists of character replacements that need to be
     * applied to remote user. The list is processed pair-wise.
     * Null (empty) is permitted in the list, which means
     * the matched character will be removed from remote user
     */
    private List remoteUserReplacementChars = new ArrayList();

    /**
     * Set of header names to be watchful for dynamic roles. Content has
     * format of Map<attribHeader, Collection<GroupMapper>>
     * where attribHeader is a string, e.g. SHIB-EP-ENTITLEMENT
     */
    private Map groupMappings = new HashMap();

    /** list of all mappers that should be doing the purging */
    private List purgeMappings = new ArrayList();

    /**
     * Whether to create accounts for new users or not
     */
    private boolean createUsers;

    /**
     * Default roles for newly created users
     */
    private List defaultRoles;

    /**
     * Automatically reload the configuration file when changed
     */
    private boolean reloadConfig;

    /**
     * When reloading the configuration file, how long to wait (in milliseconds) between
     * checking the configuration file for changes?
     */
    private long reloadConfigCheckInterval;

    /**
     * Name of the configuration file to be reloaded
     */
    private String configFile;

    /**
     * Last modified stamp of the configuration file
     */
    private long configFileLastModified;

    /**
     * System time at when the configuration file was checked the last time
     */
    private long configFileLastChecked;

    /**
     * HTTP Header name that contains a user's email address
     */
    private String emailHeaderName;

    /**
     * HTTP Header name that contains a user's full name
     */
    private String fullNameHeaderName;

    /**
     * Whether or not to update name/email info for previously created users
     */
    private boolean updateInfo;

    /**
     * Whether to update roles for new users or not
     */
    private boolean updateRoles;

    /**
     * Whether to convert fields to UTF8
     */
    private boolean convertToUTF8;

    /**
     * Whether to convert the group output to lowercase
     */
    private boolean tolowercase;

    /**
     * Whether to update last and previous login OS user properties (these are also used if using atlassian-user schema).
     */
    private boolean updateLastLogin;

    /**
     * Whether or not to automatically create groups.
     */
    private boolean autoCreateGroup;

    /**
     * Should this pluggin try to create new groups as indicated
     * by IdP (when the group value is non-existent in confluence)
     * @param autoCreateGroup if true then new groups will be automatically
     * created in confluence, otherwise they will be ignored
     */
    public void setAutoCreateGroup(boolean autoCreateGroup) {
        this.autoCreateGroup = autoCreateGroup;
    }

    public boolean isAutoCreateGroup() {
        return this.autoCreateGroup;
    }

    /**
     * Given the key (header, e.g. SHIB-EP-ENTITLEMENT),
     * return back the active group mappings that
     * can handle the key
     * @param key string to represent header
     * @return group mappers registered to handle the key
     */
    public Collection getGroupMappings(String key) {
        return (Collection) groupMappings.get(key);
    }

    public Collection getGroupMappings() {
        return groupMappings.values();
    }

    public Set getGroupMappingKeys() {
        return groupMappings.keySet();
    }

    public void setGroupMappings(Map mappings) {
        groupMappings.clear();
        groupMappings.putAll(mappings);
    }

    public void setPurgeMappings(Collection mappings) {
        purgeMappings.clear();
        purgeMappings.addAll(mappings);
    }

    public Collection getPurgeMappings() {
        return purgeMappings;
    }

    public Collection getRemoteUserMappings(){
        return remoteUserMappings;
    }
    public void setRemoteUserMappings(Collection mappings){
        remoteUserMappings.clear();
        remoteUserMappings.addAll(mappings);
    }

    public void setRemoteUserReplacementChars(List replacements){
        remoteUserReplacementChars.clear();
        remoteUserReplacementChars.addAll(replacements);
    }

    /** Iterator HAS to be processed pair-wise (e.g. entry 1 & 2)
     * where entry 1 is the chars to be replaced (regex) and
     * entry 2 is the replacement for it <bold>non-regex</bold>
     * (null means total deletion).
     *
     * @return pair-wise iterator of replacement regex
     */
    public Iterator getRemoteUserReplacementChars(){
        return remoteUserReplacementChars.iterator();
    }

    public void setOutputToLowerCase(boolean toLower){
        tolowercase = toLower;
    }

    public boolean isOutputToLowerCase(){
        return tolowercase;
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

    public boolean isReloadConfig() {
        return reloadConfig;
    }

    public void setReloadConfig(boolean reloadConfig) {
        this.reloadConfig = reloadConfig;
    }

    public long getReloadConfigCheckInterval() {
        return reloadConfigCheckInterval;
    }

    public void setReloadConfigCheckInterval(long reloadConfigCheckInterval) {
        this.reloadConfigCheckInterval = reloadConfigCheckInterval;
    }

    public String getConfigFile() {
        return configFile;
    }

    public void setConfigFile(String configFile) {
        this.configFile = configFile;
    }

    public long getConfigFileLastModified() {
        return configFileLastModified;
    }

    public void setConfigFileLastModified(long configFileLastModified) {
        this.configFileLastModified = configFileLastModified;
    }

    public long getConfigFileLastChecked() {
        return configFileLastChecked;
    }

    public void setConfigFileLastChecked(long configFileLastChecked) {
        this.configFileLastChecked = configFileLastChecked;
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

    public boolean isUpdateInfo() {
        return updateInfo;
    }

    public void setUpdateInfo(boolean updateInfo) {
        this.updateInfo = updateInfo;
    }

    public boolean isUpdateRoles() {
        return updateRoles;
    }

    public void setUpdateRoles(boolean updateRoles) {
        this.updateRoles = updateRoles;
    }

    public boolean isConvertToUTF8() {
        return convertToUTF8;
    }

    public void setConvertToUTF8(boolean convertToUTF8) {
        this.convertToUTF8 = convertToUTF8;
    }

    public boolean isUpdateLastLogin() {
        return updateLastLogin;
    }

    public void setUpdateLastLogin(boolean updateLastLogin) {
        this.updateLastLogin = updateLastLogin;
    }

    /**
     * Given a prefix and list of strings, grab all those that started
     * with 'prefix'.
     *
     * @param strings complete lists of all strings
     * @param prefix the prefix that we're looking for in a string
     * @return subset of strings that started with the given prefix
     */
    public List listPostfixes(String[] strings, String prefix) {
        List list = new ArrayList();
        for (int i = 0; i < strings.length; i++) {
            if (strings[i].startsWith(prefix)) {
                String header = strings[i].substring(prefix.length());
                if (header.length() != 0) {
                    list.add(header);
                }
            }
        }

        return list;
    }
}
