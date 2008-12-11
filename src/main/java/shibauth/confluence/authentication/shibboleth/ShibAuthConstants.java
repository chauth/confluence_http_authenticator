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
 * Neither the name of the Custom Space User Management Plugin Development Team
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

    /** convert.to.utf8 init parameter name */
    public final static String CONVERT_TO_UTF8 = "convert.to.utf8";
}
