# https://studio.plugins.atlassian.com/secure/IssueNavigator.jspa?reset=true&jqlQuery=project+%3D+SHBL+ORDER+BY+key+ASC&mode=hide

for ((x=1; x<=67; x++))
{
  curl -O https://studio.plugins.atlassian.com/browse/SHBL-$x
}
