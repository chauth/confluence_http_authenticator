/*
 Copyright (c) 2008-2014, Confluence HTTP Authenticator Team
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
 * Created 2009-01-22 to make sure the authenticator is performing efficient login flow [MELCOE]
 */

package shibauth.confluence.authentication.shibboleth;

import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.seraph.filter.BaseLoginFilter;
import com.atlassian.seraph.interceptor.LoginInterceptor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.ServletRequestWrapper;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Iterator;
import java.util.List;

/**
 * A filter that is based on Seraph's login filter. As the parent class uses username/password,
 * this filter will populate the username from remote user, and provide dummy password.
 * This filter is necessary so that Authenticator.login() is properly executed.
 */
public class ShibLoginFilter extends BaseLoginFilter {

    private final static Log log = LogFactory.getLog(ShibLoginFilter.class);

    public ShibLoginFilter() {
    }

    public String login(HttpServletRequest request, HttpServletResponse response) {
        String status = LOGIN_NOATTEMPT;
        String userid = ((HttpServletRequest) ((ServletRequestWrapper) request).getRequest()).getRemoteUser();

        //make sure remote user is set, otherwise fail
        if (userid == null) {
            return status;
        }

        List interceptors = getSecurityConfig().getInterceptors(LoginInterceptor.class);

        if (log.isDebugEnabled()) {
            log.debug("ShibLoginFilter processing login request for " + userid);
        }

        //TODO: not sure if mapping of remote-user logic needs to worry about the userid being
        // Passed to logininterceptor.beforeLogin and the getAuthenticator().login below.
        try {
            LoginInterceptor loginInterceptor;

            for (Iterator iterator = interceptors.iterator(); iterator.hasNext(); loginInterceptor.beforeLogin(request, response, userid, "", false)) {
                loginInterceptor = (LoginInterceptor) iterator.next();
            }

            boolean loggedIn = getAuthenticator().login(request, response, userid, "", false);
            status = loggedIn ? LOGIN_SUCCESS : LOGIN_FAILED;
        } catch (AuthenticatorException e) {
            status = LOGIN_FAILED;
        } finally {
            LoginInterceptor loginInterceptor;
            for (Iterator iterator = interceptors.iterator(); iterator.hasNext(); loginInterceptor.afterLogin(request, response, userid, "", false, status)) {
                loginInterceptor = (LoginInterceptor) iterator.next();
            }
        }

        return status;
    }
}
