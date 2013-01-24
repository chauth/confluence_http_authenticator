TODO: needs cleanup

{note}For those upgrading to Confluence 4.3, be sure to shib guard the mobile login path, too, e.g. /plugins/servlet/mobile/login?originalUrl=%2Fplugins%2Fservlet%2Fmobile%23dashboard%2Fpopular{note}
{warning}This is a continuation of the information provided in How to Shibbolize Confluence. Please read it first\!{warning}
{warning}The following is for an unsupported version of Shibboleth. You should avoid using this version and upgrade to a supported version of the SP instead.{warning}

h4. Apache Setup

Most of the setup is standard Shibboleth stuff, like getting the {{{nl}ServerName{nl}}} set properly and routing the right requests to Tomcat, but there are some tricks:
* Make sure requests for {{/Shibboleth.sso/\*}} don't get passed to Tomcat. If you're putting Confluence at the root, you'll probably be routing everything over, so you'll need to exclude that path with {{{nl}JkUnMount{nl}}} or the equivalent command for your connector. The commands we're using for mod_jk follow:

(note: you need at least mod_jk 1.2.8 to use JkUnMount and probably want to use mod_jk 1.2.10 or higher because of some fixes that could affect confluence in mod_jk 1.2.10.)

{code:none}LoadModule jk_module    modules/mod_jk.so

JkWorkersFile   /etc/httpd/conf/workers.properties
JkLogFile       /var/log/httpd/mod_jk.log
JkLogLevel      info

JkMount /* ajp13_worker

JkUnMount /Shibboleth.sso/* ajp13_worker
JkUnMount /shibboleth ajp13_worker
JkUnMount /shibboleth-sp/* ajp13_worker
{code}
* Create some rewrite rules to address some Java issues and local logout:

{code:none}RewriteEngine On

#This hackery is to get around an incompatibility between lazy sessions and the servlet cookie detection mechanism
RewriteRule ^/Shibboleth.sso/Login;jsessionid.*$ /Shibboleth.sso/Login [R,NE]

#This bit of hackery is to get around causing an endless loop between logout mechanisms
RewriteCond %{QUERY_STRING}  !.*done=true.*
RewriteRule ^/logout.action$ https://wiki.example.edu/Shibboleth.sso/Logout?return=https://wiki.example.edu/logout.action?done=true [R,CO=JSESSION:'':wiki.example.edu:0]
# the CO=JSESSION deletes the Tomcat session cookie which would keep the user logged in even after the Shibboleth session is destroyed

# Make sure "Login again" brings user to the dashboard and not the Logout page
RewriteCond %{QUERY_STRING} ^target=.*%2Flogout.action
RewriteRule ^/Shibboleth.sso/Login$ /Shibboleth.sso/Login?target=http://wiki.example.edu/ [R]
{code}
* To get the last rewrite rule working, also add the following into your :443 VirtualHost definition (and replace /Login with whatever you used as the login url in seraph-config.xml)

{code}
RewriteEngine On
RewriteOptions inherit
{code}
* If you are running Confluence on http but Shibboleth on https (and you are using the second form of the Seraph login URL), add also the following redirect rules to address an issue with Seraph being inconsistent in how it constructs "target" URLs Shibboleth should redirect back to.  Otherwise, automatic login to Restricted pages would break (with Shibboleth reporting {{"Session Initiator Error: Target resource was not an absolute URL."}}). Remember to replace {{/Login}} with what the login URL configured above is.

{code}
# For requests to the session initiator, rewrite relative target URLs to absolute ones.
# Ie, wherever target starts with %2F ("/), insert the host prefix there...
RewriteCond %{QUERY_STRING} ^target=%2F(.*)$
RewriteRule ^/Shibboleth.sso/Login$ /Shibboleth.sso/Login?target=http://wiki.example.edu/%1 [R,NE]
{code}

* For mod-shib make sure the following is setup, where / in the Location element would be /confluence  if you were serving confluence in /confluence instead of at the root.

(_See Shibboleth_ _[v1|https://spaces.internet2.edu/display/SHIB/WebHome]_ _documentation for more info_)

For Shibboleth v1.3\+ you'd use:

{code}
<Location />
 AuthType shibboleth
 require shibboleth
</Location>
{code}

h4. Tomcat Setup

(Assuming you are using Tomcat and Apache+mod_jk)
* In the AJP Coyote connector configuration part of server.xml, make sure you add tomcatAuthentication="false" or the REMOTE_USER header will not be communicated from Apache mod_jk to the AJP connector. For example:

{code}
<Connector port="8009" enableLookups="false" redirectPort="8443" protocol="AJP/1.3"
    tomcatAuthentication="false"/>
{code}

h4. Shibboleth SP Setup

(_See Shibboleth_ _[v1|https://spaces.internet2.edu/display/SHIB/WebHome]_ _documentation for more info_)

* Mostly standard stuff for any SP, like setting hostnames, getting a WAYF strategy in place, etc. The various options above assume that you have a SessionInitiator configured at {{/Login}} and a local logout handler at {{/Logout}}
* The {{handlerURL}} property *MUST* be set to correspond with the base of your Confluence site. If it's at the root, the default is fine. Otherwise, you'll need to prepend your base folder because of how Confluence generates login redirects, e.g. handlerURL="/confluence/Shibboleth.sso".

Note that the use of the "remote-user" or "HTTP_REMOTE_USER" header on IIS is NOT recommended, because it is not really compatible with REMOTE_USER-based applications anyway. It's better to rely on an explicit header in such cases. See the Internet2 wiki links above for more info.

h5. Shibboleth v1

* In {{AAP.xml}}, *make sure the following are uncommented* and that the Header values match the header.fullname and header.email above without any quotes or spaces in the properties file, as mentioned previously. Change the attribute names to match the mace attribute/etc. of the variable that is passed in from the IdP:

{code}
...

<AttributeRule Name="urn:mace:dir:attribute-def:eduPersonPrincipalName" Scoped="true" Header="REMOTE_USER" Alias="user">
  <AnySite>
    <Value Type="regexp">^[How to Shibbolize Confluence Using Shibboleth 1.3^@]+$</Value>
  </AnySite>
</AttributeRule>

...

<AttributeRule Name="urn:mace:dir:attribute-def:mail" Header="Shib-InetOrgPerson-mail">
  <AnySite>
    <AnyValue/>
  </AnySite>
</AttributeRule>

...

<AttributeRule Name="urn:mace:dir:attribute-def:displayName" Header="Shib-InetOrgPerson-displayName">
  <AnySite>
    <AnyValue/>
  </AnySite>
</AttributeRule>
...
{code}

h4. Shibboleth IdP Setup

(_See Shibboleth_ _[v1|https://spaces.internet2.edu/display/SHIB/WebHome]_ _documentation for more info_)

* Make sure that it is "turned on" for the IdP to provide the following as defined about halfway down the instruction page for [http://middleware.internet2.edu/docs/internet2-spaces-instructions-200703.html]. (Thanks to Steve Olshansky for this info)
** urn:mace:dir:attribute-def:mail
** urn:mace:dir:attribute-def:displayName