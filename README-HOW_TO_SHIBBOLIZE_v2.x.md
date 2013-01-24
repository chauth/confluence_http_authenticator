TODO: needs cleanup

{note}For those upgrading to Confluence 4.3, be sure to shib guard the mobile login path, too, e.g. /plugins/servlet/mobile/login?originalUrl=%2Fplugins%2Fservlet%2Fmobile%23dashboard%2Fpopular{note}

{warning}This is a continuation of the information provided in [How to Shibbolize Confluence]. Please read it first\!{warning}

{warning}The following may be outdated and is probably incomplete. For more accurate and comprehensive information about Shibboleth, please see: [https://wiki.shibboleth.net/confluence/display/SHIB2]{warning}

h4. Apache Setup

Most of the setup is standard Shibboleth stuff, like getting the {{{nl}ServerName{nl}}} set properly and routing the right requests to Tomcat, but there are some tricks:

* Make sure requests for {{/Shibboleth.sso/\*}} don't get passed to Tomcat. If you're putting Confluence at the root, you'll probably be routing everything over, so you'll need to exclude that path with the appropriate command for your connector. With the recommended use of mod_proxy_ajp:

{code:none}LoadModule proxy_ajp_module modules/mod_proxy_ajp.so

ProxyPass /Shibboleth.sso !
ProxyPass /shibboleth-sp !
ProxyPass / ajp://localhost:8009/ timeout=360
{code}

* Create some rewrite rules to address some Java issues and local logout:

{code:none}RewriteEngine On

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

* For the SP itself to activate, make sure the following is setup, where / in the Location element would be /confluence  if you were serving confluence in /confluence instead of at the root.

(_See Shibboleth_ _[v2|https://wiki.shibboleth.net/confluence/display/SHIB2]_ _documentation for more info_)

Make sure to enable the {{ShibUserHeaders}} option because, by default, the SP populates environment variables rather than HTTP Headers, and the Conflence Authenticator currently is header-aware only.

{code}
<Location />
 AuthType shibboleth
 require shibboleth
 ShibUseHeaders On
</Location>
{code}

h4. Tomcat Setup

(Assuming you are using Tomcat and Apache+mod_jk)
* In the AJP Coyote connector configuration part of server.xml, make sure you add tomcatAuthentication="false" or the REMOTE_USER header will not be communicated from Apache mod_jk to the AJP connector. For example:

{code}
<Connector port="8009" enableLookups="false" redirectPort="8443" protocol="AJP/1.3"
    tomcatAuthentication="false"/>
{code}

h4. Additional Shibboleth SP Setup

(_See the_ _[Shibboleth documentation|https://wiki.shibboleth.net/confluence/display/SHIB2]_ _for more info_)

* Mostly standard stuff for any SP, like setting hostnames, getting an IdP discovery strategy in place, etc. The various options above assume that you have a SessionInitiator configured at {{/Login}} and a local logout handler at {{/Logout}}
* The {{handlerURL}} property *MUST* be set to correspond with the base of your Confluence site. If it's at the root, the default is fine. Otherwise, you'll need to prepend your base folder because of how Confluence generates login redirects, e.g. handlerURL="/confluence/Shibboleth.sso".

Note that the use of the "remote-user" or "HTTP_REMOTE_USER" header on IIS is NOT recommended, because it is not really compatible with REMOTE_USER-based applications anyway. It's better to rely on an explicit header in such cases. See the Shibboleth documentation for more information.

* In {{shibboleth2.xml}}, make sure REMOTE_USER contains the attribute that you want to use as the username in Confluence, e.g. if "userid" was the header name containing the username, and if that isn't set you would use eppn, etc. you might have:

{code}
<ApplicationDefaults id="default" policyId="default"
    entityID="https://myserver.acme.org"
    REMOTE_USER="userid eppn ...">
...
{code}

* In {{attribute-map.xml}}, you probably want to uncomment these, and possibly change the id to whatever header names you prefer. Please see [Attribute Access|https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPAttributeAccess] in the Shibboleth documentation for more info. In the example shown, both SAML 1 and SAML 2 attribute names for the same information are configured.

{code}
...
<Attribute name="urn:mace:dir:attribute-def:mail" id="mail"/>
<Attribute name="urn:mace:dir:attribute-def:displayName" id="displayName"/>
<Attribute name="urn:oid:0.9.2342.19200300.100.1.3" id="mail"/>
<Attribute name="urn:oid:2.16.840.1.113730.3.1.241" id="displayName"/>
...
{code}

h4. Shibboleth IdP Setup

When used with a Shibboleth SP, the IdP needs no particular special behavior, but obviously you'll need to release the attributes you want to use to populate the username, full name, and e-mail address fields in Confluence.

You can also use more advanced features of the Shibboleth Authenticator to leverage additional attributes from the IdP to manage groups or roles.