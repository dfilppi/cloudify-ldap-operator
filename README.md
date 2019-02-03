# Cloudify LDAP Operator

Sample implementation of an LDAP "operator" for Cloudify.  Basic idea: respond to changes in LDAP entries by running Cloudify workflows.  Example use case: program network to give or remove access to a resource based on a user's membership in a particular LDAP group (ou).
