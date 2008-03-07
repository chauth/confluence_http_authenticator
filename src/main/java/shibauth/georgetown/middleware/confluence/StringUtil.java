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

import java.util.ArrayList;
import java.util.List;


public class StringUtil {

    /** Define split characters **/
    private final static String SEPARATOR = "[,;]";

    public static List toListOfNonEmptyStringsDelimitedByCommaOrSemicolon( String s ) {
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

}
