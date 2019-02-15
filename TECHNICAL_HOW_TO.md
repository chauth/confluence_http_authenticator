Technical Howto and Hints
=====

This explains how to build and release the plugin.

## Building

Build assumes Java 6+ (7+ since 2.6.x releases), Maven 3+. Atlassian SDK does not need to be installed, as it is an authenticator jar loaded on
classpath, not a plugin, nor can it or should it be, even in Confluence 4.x+.

For larger changes, you'd want to create an [issue][issues] first to ask if it would be something that would be of interest to everyone.

Please discuss publically within an [issue][issues] in GitHub. Otherwise, consider sending an email directly to one or more team members.

Releases can be found [here][releases].

To build, type:

    mvn clean install

When committing, please try to include the issue number when possible in the beginning on the comment, e.g.:

    git commit -m "#123 Added compatibility for Confluence v2.5"

## Releasing a New Version

### To release a new version:

1. Add yourself to the list of developers in the pom.xml.

2. Build and manually test jar in target/*.jar (or have someone test)

    mvn clean install

3. Edit pom.xml to be new release version (remove "-SNAPSHOT" from release version, e.g. change from 1.2.3-SNAPSHOT to 1.2.3)

4. Build and manually test again as needed (or have someone test)

    mvn clean install

5. Put changes from git log into release info in the CHANGELOG.md (note: prior releases used Jira ticket id, but newer releases should use the #(GitHub issue num) format, e.g. "#123 Added compatibility for Confluence v2.5").

6. Copy new release to releases directory, add pom.xml change and new release, commit, and push, then tag, and push tags:

```sh

cp target/(name of jar).jar releases/
      git add releases
      git add pom.xml
      git commit -m "releasing 1.2.3"
      git push
      git tag v1.2.3
      git push --tags
```

7. Edit pom.xml to increment patch version and add "-SNAPSHOT" to version (e.g. change from 1.2.3 to 1.2.4-SNAPSHOT).

8. Add pom.xml, commit, and push.

```sh
   git add pom.xml
   git commit -m "incrementing pom.xml version to 1.2.4-SNAPSHOT"
	 git push
```

9. Add release info/jar also to (this url may change):

      https://plugins.atlassian.com/plugins/shibauth.confluence.authentication.shibboleth

10. Have fun!

### Release Notes

See git log or the [CHANGELOG][changelog]


[changelog]: http://github.com/chauth/confluence_http_authenticator/blob/master/CHANGELOG.md
[issues]: https://github.com/chauth/confluence_http_authenticator/issues
[releases]: https://github.com/chauth/confluence_http_authenticator/releases