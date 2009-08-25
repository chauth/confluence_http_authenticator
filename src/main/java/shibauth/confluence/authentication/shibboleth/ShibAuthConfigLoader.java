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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class ShibAuthConfigLoader {

    private final static Log log =
        LogFactory.getLog(ShibAuthConfigLoader.class);

    public static ShibAuthConfiguration getShibAuthConfiguration(
        ShibAuthConfiguration oldConfig) {
        if (log.isDebugEnabled()) {
            if (oldConfig == null) {
                log.debug(
                    "Initializing authenticator using property resource " +
                    ShibAuthConstants.PROPERTIES_FILE);
            } else {
                log.debug("Reloading configuration from authenticator from file " + oldConfig.
                    getConfigFile());
            }
        }

        ShibAuthConfiguration config = new ShibAuthConfiguration();

        try {

            InputStream propsIn = null;
            if (oldConfig == null) {
                propsIn =
                    RemoteUserAuthenticator.class.getResourceAsStream(
                    ShibAuthConstants.PROPERTIES_FILE);
            } else {
                propsIn = new FileInputStream(oldConfig.getConfigFile());
            }

            Properties configProps = new Properties();
            configProps.load(propsIn);

            // Load create.users property
            config.setCreateUsers(Boolean.valueOf(
                configProps.getProperty(ShibAuthConstants.CREATE_USERS)).
                booleanValue());

            if (log.isDebugEnabled()) {
                log.debug(
                    "Setting create new users to " + config.isCreateUsers());
            }

            // Load update.info property
            config.setUpdateInfo(Boolean.valueOf(
                configProps.getProperty(ShibAuthConstants.UPDATE_INFO)).
                booleanValue());

            if (log.isDebugEnabled()) {
                log.debug("Setting update user information to " +
                    config.isUpdateInfo());
            }

            // Load update.lastLoginDate property
            config.setUpdateLastLogin(Boolean.valueOf(
                configProps.getProperty(ShibAuthConstants.UPDATE_LAST_LOGIN_DATE)).
                booleanValue());

            if (log.isDebugEnabled()) {
                log.debug("Setting update user's last login date and previous login date information to " + config.
                    isUpdateLastLogin());
            }

            // Load update.roles property
            config.setUpdateRoles(Boolean.valueOf(
                configProps.getProperty(ShibAuthConstants.UPDATE_ROLES)).
                booleanValue());

            if (log.isDebugEnabled()) {
                log.debug(
                    "Setting update user roles to " + config.
                    isUpdateRoles());
            }

            // Load reload.config property
            config.setReloadConfig(Boolean.valueOf(
                configProps.getProperty(ShibAuthConstants.RELOAD_CONFIG)).
                booleanValue());

            if (log.isDebugEnabled()) {
                log.debug("Setting reload config to " + config.isReloadConfig());
            }

            // Load reload.config.check.interval property
            String reloadConfigCheckIntervalS = configProps.getProperty(
                ShibAuthConstants.RELOAD_CONFIG_CHECK_INTERVAL);
            if (reloadConfigCheckIntervalS != null) {
                config.setReloadConfigCheckInterval(Long.valueOf(
                    reloadConfigCheckIntervalS).longValue());

                if (log.isDebugEnabled()) {
                    log.debug("Setting reload config check interval to " +
                        config.getReloadConfigCheckInterval());
                }
            }

            // Load convert.to.utf8 property
            config.setConvertToUTF8(Boolean.valueOf(
                configProps.getProperty(ShibAuthConstants.CONVERT_TO_UTF8)).
                booleanValue());

            if (log.isDebugEnabled()) {
                log.debug("Setting convert header values to UTF-8 to " +
                    config.isConvertToUTF8());
            }

            // Load dynamicheaders.output.tolowercase property
            // default is true when not existing
            config.setOutputToLowerCase(Boolean.valueOf(
                configProps.getProperty(ShibAuthConstants.ROLES_OUTPUT_TOLOWER,"true")).
                booleanValue());

            if (log.isDebugEnabled()) {
                log.debug("Setting convert group output values to lowercase = " +
                    config.isOutputToLowerCase());
            }

            // Load default roles
            List defaultRoles = new ArrayList();

            String roles = configProps.getProperty(
                ShibAuthConstants.DEFAULT_ROLES);

            if (roles != null) {

                defaultRoles.addAll(StringUtil.
                    toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(roles));

                if (log.isDebugEnabled()) {
                    for (Iterator it =
                        defaultRoles.iterator(); it.hasNext();) {
                        log.debug(
                            "Adding role " + it.next().toString() +
                            " to list of default user roles");
                    }
                }
            }

            config.setDefaultRoles(defaultRoles);

            config.setFullNameHeaderName(configProps.getProperty(
                ShibAuthConstants.FULLNAME_HEADER_NAME_PROPERTY));

            if (log.isDebugEnabled()) {
                log.debug(
                    "HTTP Header that may contain user's full name set to: " + config.
                    getFullNameHeaderName());
            }

            config.setEmailHeaderName(configProps.getProperty(
                ShibAuthConstants.EMAIL_HEADER_NAME_PROPERTY));

            if (log.isDebugEnabled()) {
                log.debug(
                    "HTTP Header that may contain user's email address set to: " + config.
                    getEmailHeaderName());
            }

            // Load property using.shib.login.filter
            config.setUsingShibLoginFilter(Boolean.valueOf(
                configProps.getProperty(ShibAuthConstants.USING_SHIB_LOGIN_FILTER)).
                booleanValue());

            if (log.isDebugEnabled()) {
                log.debug("Setting usingShibLoginFilter to " +
                    config.isUsingShibLoginFilter() + " (change to this must accompany manual changes to web.xml)");
            }

            loadGroupMapping(config, configProps);
            loadPurgeGroupMapping(config, configProps);
            loadRemoteUserMapping(config,configProps);
            loadFullNameMapping(config,configProps);

            // Set the name of the config file for automatic reloading
            if (config.isReloadConfig()) {

                URL configURL = RemoteUserAuthenticator.class.getResource(
                    ShibAuthConstants.PROPERTIES_FILE);

                if ((configURL == null) || !configURL.getProtocol().equals(
                    "file")) {
                    log.error(
                        "Configuration file is not a file URL, cannot setup automatic reloading from: " + configURL);
                } else {

                    String configFile = configURL.getFile();
                    long configFileLastModified = new File(configFile).
                        lastModified();

                    config.setConfigFile(configFile);
                    config.setConfigFileLastModified(configFileLastModified);
                    config.setConfigFileLastChecked(System.currentTimeMillis());

                    log.info("Setting config file name to " + configFile +
                        " with a lastModified stamp of " +
                        configFileLastModified +
                        " and a last checked stamp of " +
                        config.getConfigFileLastChecked());
                }
            }

        } catch (IOException e) {
            log.warn(
                "Unable to read properties file, using default properties", e);
        }

        return config;
    }

    private static void loadPurgeGroupMapping(ShibAuthConfiguration config,
        Properties configProps) {
        List purgeRolesRegex = StringUtil.
            toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(configProps.
            getProperty(ShibAuthConstants.PURGE_ROLES));
        if (purgeRolesRegex.isEmpty()) {
            log.debug("No roles regex specified, no roles will be purged.");
            return;
        }

        //cheat a bit, the syntax:
        //purge.roles = regex1, regex2
        //we convert it to GroupMapper's syntax where
        //  match = regex1
        //  transform = $0 (the whole input string; equiv to null here)
        //  case insensitive
        Collection purgeRolesGroups = new ArrayList(purgeRolesRegex.size());
        for (int i = 0; i < purgeRolesRegex.size(); i++) {
            String regex = purgeRolesRegex.get(i).toString();
            purgeRolesGroups.add(new GroupMapper("purge-" + i, regex, null,
                false));
            log.debug("Roles matching (" + regex + ") are to be purged.");
        }
        config.setPurgeMappings(purgeRolesGroups);
    }

    private static void loadRemoteUserMapping(ShibAuthConfiguration config,
        Properties configProps) {
        //remoteuser=remoteusermap
        //remoteuser.replace=\\#,A,\\%,c,-,,
        //remoteuser.remoteusermap.match=some-regex
        List remoteuserlabels = StringUtil.
                toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(
                configProps.getProperty(
                ShibAuthConstants.REMOTEUSER_PREFIX));

        if (remoteuserlabels.isEmpty()) {
            //clear the headers, future processing wil bypass when empty
            config.setRemoteUserMappings(Collections.EMPTY_LIST);
            return;
        }

        List replacements = StringUtil.
            toListOfStringsDelimitedByCommaOrSemicolon(
            configProps.getProperty(ShibAuthConstants.REMOTEUSER_REPLACEMENT)
            );

        config.setRemoteUserReplacementChars(replacements);

        List mappers = new ArrayList();

        mappers.addAll(loadMappers(ShibAuthConstants.REMOTEUSER_MAP_PREFIX, configProps, remoteuserlabels));

        if (mappers.isEmpty()) {
            log.debug(
                "No RemoteUser mapper handler defined in \"" +
                ShibAuthConstants.REMOTEUSER_PREFIX +
                "\", remoteuser will be left untouched.");
            config.setRemoteUserMappings(Collections.EMPTY_LIST);
            return;
        }
        log.debug("RemoteUser mapping is defined in config, transformation of remote user will happen during logins");
        config.setRemoteUserMappings(mappers);
    }

    private static void loadFullNameMapping(ShibAuthConfiguration config,
        Properties configProps) {
        //fullname=fullnamemap
        //fullname.replace=\\#,A,\\%,c,-,,
        //fullname.fullnamemap.match=some-regex
        List fullnamelabels = StringUtil.
                toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(
                configProps.getProperty(
                ShibAuthConstants.FULL_NAME_PREFIX));

        if (fullnamelabels.isEmpty()) {
            //clear the headers, future processing wil bypass when empty
            config.setFullNameMappings(Collections.EMPTY_LIST);
            return;
        }

        List replacements = StringUtil.
            toListOfStringsDelimitedByCommaOrSemicolon(
            configProps.getProperty(ShibAuthConstants.FULL_NAME_REPLACEMENT)
            );

        config.setFullNameReplacementChars(replacements);

        List mappers = new ArrayList();

        mappers.addAll(loadMappers(ShibAuthConstants.FULL_NAME_MAP_PREFIX, configProps, fullnamelabels));

        if (mappers.isEmpty()) {
            log.debug(
                "No FullName mapper handler defined in \"" +
                ShibAuthConstants.FULL_NAME_PREFIX +
                "\", full name will be left untouched.");
            config.setFullNameMappings(Collections.EMPTY_LIST);
            return;
        }
        log.debug("FullName mapping is defined in config, transformation of full name will happen during logins");
        config.setFullNameMappings(mappers);
    }

    private static void loadGroupMapping(ShibAuthConfiguration config,
        Properties configProps) {

        config.setAutoCreateGroup(Boolean.valueOf(
            configProps.getProperty(ShibAuthConstants.AUTO_CREATE_GROUP)).
            booleanValue());
        log.debug("Setting automatic creation of new group to " + config.
            isAutoCreateGroup());

        // Load dynamic roles property
        //#header.dynamicroles.SHIB-EP-ENTITLEMENT=mapper1, mapper2
        //"headers" contains the list of entries such as "SHIB-EP-ENTITLEMENT"
        List headers = config.listPostfixes((String[]) configProps.
            keySet().toArray(new String[0]),
            ShibAuthConstants.ROLES_HEADER_PREFIX);

        //no header is specified for dynamicgroup
        if (headers.isEmpty()) {
            log.info(
                "No attribute header defined for dynamicroles, deactivating it.");
            //clear the headers, future processing wil bypass when empty
            config.setGroupMappings(Collections.EMPTY_MAP);
            return;
        }

        //Map<mapper_string_name, GroupMapper>
        Map allMappers = new HashMap();

        //Map<header_name, Collection<GroupMapper>>
        Map groupMappings = new HashMap();
        for (Iterator headerIt = headers.iterator(); headerIt.hasNext();) {
            String header = headerIt.next().toString();
            List definedMapperStrings = StringUtil.
                toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(
                configProps.getProperty(
                ShibAuthConstants.ROLES_HEADER_PREFIX + header));

            List mappers = new ArrayList();

            //check if the definedMapperStrings already loaded previously
            //if so, just reuse the same definition
            for (Iterator definedIterator = definedMapperStrings.iterator();
                definedIterator.hasNext();) {
                GroupMapper gMapper = (GroupMapper) allMappers.get(
                    definedIterator.next().toString());
                if (gMapper != null) {
                    mappers.add(gMapper);

                    //remove it from definedMapperStrings so that we don't
                    //load it twice
                    definedIterator.remove();
                }
            }

            mappers.addAll(loadMappers(ShibAuthConstants.ROLES_ATTRIB_PREFIX,configProps, definedMapperStrings));

            if (mappers.isEmpty()) {
                log.debug(
                    "No group mapper handler defined in \"" +
                    ShibAuthConstants.ROLES_HEADER_PREFIX + header +
                    "\", ignoring this header.");
                continue;
            }
            //cache the mappers and print them
            StringBuffer sb = new StringBuffer();
                for (Iterator it = mappers.iterator(); it.hasNext();) {
                    GroupMapper mapper = (GroupMapper) it.next();
                    String label = mapper.toString();
                    sb.append(label);
                    if (it.hasNext()) {
                        sb.append(", ");
                    }

                    //fill up allMappers, so that we dont need to reload
                    //existing mappers later
                    if (!allMappers.containsKey(label)) {
                        allMappers.put(label, mapper);
                    }
                }
                log.debug("Successfully loading mapper for header=" + header +
                    ", handlers=" + sb.toString());
            groupMappings.put(header, mappers);
        }
        config.setGroupMappings(groupMappings);
    }

    private static Collection loadMappers(String mapperPrefix, Properties configProps,
        List mapperStrings) {
        if (mapperStrings == null || mapperStrings.isEmpty()) {
            return Collections.EMPTY_LIST;
        }
        Collection mappers = new ArrayList();
        for (int i = 0; i < mapperStrings.size(); i++) {
            String name = (String) mapperStrings.get(i);
            String mapperStr = mapperPrefix + name;
            String match = configProps.getProperty(
                mapperStr + ShibAuthConstants.PART_MATCH);
            String transform = configProps.getProperty(
                mapperStr + ShibAuthConstants.PART_TRANSFORM);

            if (match == null && transform == null) {
                log.warn(
                    "Fail to load group mapper with label=" + name + ", ignoring this mapper.");
                continue;
            }

            boolean sensitive = Boolean.valueOf(configProps.getProperty(
                mapperStr + ShibAuthConstants.PART_SENSITIVE, "true")).booleanValue();
            GroupMapper mapper = new GroupMapper(name, match, transform,
                sensitive);
            mappers.add(mapper);
        }
        return mappers;
    }
}
