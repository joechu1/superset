import logging
from superset.security import SupersetSecurityManager

log = logging.getLogger(__name__)

class CustomSsoSecurityManager(SupersetSecurityManager):

    def get_oauth_user_info(self, provider, resp):
        log.debug("Oauth2 provider: {0}.".format(provider))

        # for Azure AD Tenant. Azure OAuth response contains
        # JWT token which has user info.
        # JWT token needs to be base64 decoded.
        # https://docs.microsoft.com/en-us/azure/active-directory/develop/
        # active-directory-protocols-oauth-code
        if provider == "azure":
            log.debug("Azure response received : {0}".format(resp))
            id_token = resp["id_token"]
            log.debug(str(id_token))
            me = self._azure_jwt_token_parse(id_token)
            log.debug("Parse JWT token : {0}".format(me))
            return {
                "name": me.get("name", ""),
                "email": me["upn"],
                "first_name": me.get("given_name", ""),
                "last_name": me.get("family_name", ""),
                "id": me["oid"],
                "username": me["preferred_username"],
            }
