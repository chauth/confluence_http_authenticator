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
     * purge.roles init parameter name
     */
    public final static String PURGE_ROLES = "purge.roles";

    /**
     * reload.config init parameter name
     */
    public final static String RELOAD_CONFIG = "reload.config";

    /**
     * reload.config.check.interval init parameter name
     */
    public final static String RELOAD_CONFIG_CHECK_INTERVAL = "reload.config.check.interval";

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
     * Prefix to be used for mapping of different roles. i.e.
     * dynamicroles.header.SHIB-EP-ENTITLEMENT=label1, label2
     *
     * See #ROLES_ATTRIB_PREFIX
     */
    public final static String ROLES_HEADER_PREFIX =
        "dynamicroles.header.";

    /**
     * Prefix to be used for mapping of different roles. i.e.
     * dynamicroles.mapper.label1.match=regex
     * dynamicroles.mapper.label1.transform= group1, group2, $2
     */
    public final static String ROLES_ATTRIB_PREFIX = "dynamicroles.mapper.";

    /**
     * Label to represent indicate whether the group be automatically created
     * when the IdP provides new group non-existent in confluence.
     */
    public final static String AUTO_CREATE_GROUP = "dynamicroles.auto_create_role";

    public final static String PART_MATCH = ".match";
    public final static String PART_TRANSFORM = ".transform";
    public final static String PART_SENSITIVE = ".casesensitive";

    /**
     * update.info init parameter name
     */
    public final static String UPDATE_INFO = "update.info";

    /**
     * update.last.login.date init parameter name
     */
    public final static String UPDATE_LAST_LOGIN_DATE = "update.last.login.date";

    /** update.roles init parameter name */
    public final static String UPDATE_ROLES = "update.roles";

    /** convert.to.utf8 init parameter name */
    public final static String CONVERT_TO_UTF8 = "convert.to.utf8";
}
