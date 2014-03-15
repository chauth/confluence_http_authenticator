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

package shibauth.confluence.authentication.shibboleth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * GroupMapper is capable to process an incoming value(s) and
 * producing the output desired as specified by the mapping regex.
 * The properties that can be specified in this class:
 * <ul>
 * <li>match = the regex to which the incoming header to be matched</li>
 * <li>transform = the regex that is responsible to produce the expected output
 * once "match" is successful</li>
 * <li>casesensitive= boolean value whether to be sensitive about matching
 * the input. default is true</li>
 * <li>retract = boolean value whether this mapping should remove a particular
 * group from user. default is false</li>
 * <li>force = boolean value to decide whether this mapper will override any
 * other mappers' result (with respect to the same group). default is false</li>
 * </ul>
 * <p/>
 * The processing logic is as follow:
 * <ol>
 * <li>an input such as "urn:abc:xyz" which represents a group is evaluated</li>
 * <li>supposed match regex = urn\:(abc)\:(.*)</li>
 * <li>supposed transform = $1_$2</li>
 * <li>initially the groupmapper will check whether the input satisfies
 * its 'match' regex, if so then this mapper is activated</li>
 * <li>it then check whether a specific transform is defined, if so
 * the transform is executed (if it is not explicitly defined, the output
 * will be exactly whatever the outcome of match regex which is the same as
 * the input</li>
 * <li>if retract is set to true, then this mapper will perform reversal of
 * previously made mapping (e.g. it will remove the user from confluence's
 * group matching the output rather than adding the user to the group;
 * purging the roles). This only <strong>happens</strong> when there
 * is <strong>no</strong> other mappers explicitly requiring the user
 * to be added to the group (e.g. allow-overide combining algorithm)
 * and none other mappers that process the same output has explicitly
 * specify its "force" attribute to be true.</li>
 * <li>if force is true, then the outcome of this mapper takes precedence</li>
 * </ol>
 * <p/>
 * Two or more mappers that produce the same output (group) and have their "force"
 * attribute specified to be true will have undefined result (1 of these
 * mappers will win, but dont know which one ;)
 * <p/>
 * This mapper, when placed in sorted list, will be placed at the back of the
 * list if its 'force' attribute is set to true.
 */
public class GroupMapper {
    private String matchRegex;
    private String transform;
    private String name;
    private boolean sensitive = true;
    private final static Log log = LogFactory.getLog(GroupMapper.class);

    /**
     * Make a new group mapper processor. Pay attention to the inputs as
     * they carry specific meanings on null or empty strings.
     *
     * @param name      name of this mapper, this could be any labels
     * @param match     regex to do the matching of inputs, leave as null to match
     *                  against any inputs (e.g. always return positive match)
     * @param transform to transform and produce the output, leave as null
     *                  if this mapper should only use exact string in the input (provided the
     *                  match is successful). this has passthrough effect for matched regex.
     * @param sensitive should the matching be case sensitive
     */
    public GroupMapper(String name, String match, String transform, boolean sensitive) {
        this.name = name;
        setMatchRegex(match);
        setTransform(transform);
        this.sensitive = sensitive;
    }

    public boolean isCaseSensitive() {
        return sensitive;
    }

    public void setCaseSensitive(boolean sensitive) {
        this.sensitive = sensitive;
    }

    /**
     * Go through the following processing logic:
     * <ul>
     * <li>'match' logic: check if the input matches the 'match' regex, if
     * so continue perform the regex groupings (if exist) and continue to
     * 'transform' logic</li>
     * <li>if 'match' regex is null but 'transform' exists, continue to
     * transform logic</li>
     * <li>'transform' logic: if transform is null, then return the
     * value, otherwise perform value transformation depend on the regex specified
     * in 'transform'</li>
     * </ul>
     * <p/>
     * Transform string can be separated by comma to indicate
     * multiple groups in confluence, e.g. $1, $3 means anything
     * that matches 'match' regex will cause group 1 and 3 becoming
     * confluence groups.
     *
     * @param initValue if this value is null or empty, then only
     *                  GroupManager <strong>without</strong> 'match' regex is executed. if
     *                  transform is also null, then it simply return null output
     * @return the final group output value. if there are multiple groups
     *         they are separated by comma or semicolon (provided match regex or
     *         transform has specified the comma/semicolon
     */
    public String process(String initValue) {
        String value = initValue;
        if (value == null) {
            value = "";
        }

        if (value.length() == 0) {
            if (matchRegex == null && transform == null) {
                return null;
            }
        }

        String regex = matchRegex;
        //accept any input
        if (matchRegex == null) {
            regex = ".*";
        }

        //perform matches first
        Pattern p = null;
        if (isCaseSensitive()) {
            p = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        } else {
            p = Pattern.compile(regex);
        }

        Matcher m = p.matcher(value);
        if (!m.matches()) {
            // this has been helpful for users that are debugging their regexp
            if (log.isDebugEnabled()) {
                log.debug("Regexp '" + regex + "' did not match value='" + value + "'");
            }
            return null;
        }

        //perform transformation replacements
        //TODO: any better way of doing this??
        String t = transform;
        if (t == null) {
            t = value;
        }

        for (int i = m.groupCount(); i > 0; i--) {
            if (log.isDebugEnabled()) {
                log.debug("The group identified $" + i + "=" + m.group(i));
            }

            t = t.replaceAll("\\$" + i, m.group(i));
        }

        //in case someone uses $0
        t = t.replaceAll("\\$0", m.group(0));

        if (log.isDebugEnabled()) {
            log.debug("Converted: value=" + value + " to group=" + t);
        }

        return t;
    }

    /**
     * Simply return the label/name of this group mapper
     */
    public String toString() {
        return name;
    }

    public String getMatchRegex() {
        return matchRegex;
    }

    public String getTransform() {
        return transform;
    }

    public void setMatchRegex(String regex) {
        if (regex != null && regex.trim().length() == 0) {
            regex = null;
        }

        matchRegex = regex;
    }

    public void setTransform(String transform) {
        if (transform != null && transform.trim().length() == 0) {
            transform = null;
        }

        this.transform = transform;
    }
}
