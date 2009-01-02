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

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;


public class StringUtil {

    private final static Log log = LogFactory.getLog(StringUtil.class);

    /**
     * Define split characters *
     */
    private final static String SEPARATOR = "[,;]";

    public static List toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(String s) {
        List results = new ArrayList();

        String[] terms = s.split(SEPARATOR);

        for (int i = 0; i < terms.length; i++) {
            String term = terms[i].trim();
            if (term.length() > 0) {
                results.add(term);
            }
        }
        return results;
    }

    public static String convertToUTF8(String s) {
        String converted = null;
        if (s != null) {
            try {
                converted = new String(s.getBytes("UTF-8"));
                if (log.isDebugEnabled()) {
                    log.debug("Fixed fullname '" + s + "' to UTF-8 '" + converted + "'.");
                }

            } catch (UnsupportedEncodingException ue) {
                log.error("Unable to set UTF-8 character encoding for user '" + s + "'!", ue);
            }
        }

        return converted;
    }
}
