from authlib.jose.errors import JoseError
from authlib.jose import jwt
class RPInitiatedLogoutEndpoint:
    """"""

    ENDPOINT_NAME = "rp_initiated_logout"

    def __init__(self, server):
        self.server = server

    def __call__(self, request):
        return self.create_logout_response(request)

    def create_logout_response(self, request, grant_user):

        # [post_logout_redirect_uri] MAY use the http scheme, provided that the Client Type is confidential, as defined in Section 2.1 of OAuth 2.0 [RFC6749], and provided the OP allows the use of http RP URIs
        ...

        # [post_logout_redirect_uri] The value MUST have been previously registered with the OP, either using the post_logout_redirect_uris

        # 	RPs MAY use the HTTP GET or POST methods to send the logout request to the OP.self
        id_token_hint = request.args.get("id_token_hint")
        logout_hint = request.args.get("logout_hint")
        client_id = request.args.get("client_id")
        post_logout_redirect_uri = request.args.get("post_logout_redirect_uri")
        ui_locales = request.args.get("ui_locales")
        state = request.args.get("state")

        client = self.authenticate_client(request)


        # When an id_token_hint parameter is present, the OP MUST validate that it was the issuer of the ID Token.
        if id_token_hint:
            try:
                id_token = jwt.decode(
                    id_token_hint,
                    key=self.get_jwks(),
                )

            except DecodeError:
                raise InvalidTokenError(
                )
        else:
            id_token = None

        # When both client_id and id_token_hint are present, the OP MUST verify that the Client Identifier matches the one used when issuing the ID Token.
        if id_token_hint and client_id:
            ...

            # The OP SHOULD accept ID Tokens when the RP identified by the ID Token's aud claim and/or sid claim has a current session or had a recent session at the OP, even when the exp time has passed. If the ID Token's sid claim does not correspond to the RP's current session or a recent session at the OP, the OP SHOULD treat the logout request as suspect, and MAY decline to act upon it.
            ...

        # TODO: récupérer les deux types de vars
        result = self.delegate(
            id_token_hint=id_token_hint,
            logout_hint=logout_hint,
            client_id=client_id,
            post_logout_redirect_uri=post_logout_redirect_uri,
            ui_locales=ui_locales,
        )

        # As part of the OP logging out the End-User, the OP uses the logout mechanism(s) registered by the RPs to notify any RPs logged in as that End-User that they are to likewise log out the End-User. RPs can use any of OpenID Connect Session Management 1.0 [OpenID.Session], OpenID Connect Front-Channel Logout 1.0 [OpenID.FrontChannel], and/or OpenID Connect Back-Channel Logout 1.0 [OpenID.BackChannel] to receive logout notifications from the OP, depending upon which of these mechanisms the OP and RPs mutually support. The RP initiating the logout is to be included in these notifications before the post-logout redirection defined in Section 3 is performed.
        ...


        # In some cases, the RP will request that the End-User's User Agent to be redirected back to the RP after a logout has been performed. Post-logout redirection is only done when the logout is RP-initiated, in which case the redirection target is the post_logout_redirect_uri parameter value sent by the initiating RP. An id_token_hint carring an ID Token for the RP is also RECOMMENDED when requesting post-logout redirection; if it is not supplied with post_logout_redirect_uri, the OP MUST NOT perform post-logout redirection unless the OP has other means of confirming the legitimacy of the post-logout redirection target. The OP also MUST NOT perform post-logout redirection if the post_logout_redirect_uri value supplied does not exactly match one of the previously registered post_logout_redirect_uris values. The post-logout redirection is performed after the OP has finished notifying the RPs that logged in with the OP for that End-User that they are to log out the End-User. 
        # TODO: check that post_logout_redirect_uri is valid 

        # [state] 	Opaque value used by the RP to maintain state between the logout request and the callback to the endpoint specified by the post_logout_redirect_uri parameter. If included in the logout request, the OP passes this value back to the RP using the state parameter when redirecting the User Agent back to the RP.
        return post_logout_redirect_uri + state

    def endpoint_return(
        self,
        # The OP SHOULD accept ID Tokens when the RP identified by the ID Token's aud claim and/or sid claim has a current session or had a recent session at the OP, even when the exp time has passed. If the ID Token's sid claim does not correspond to the RP's current session or a recent session at the OP, the OP SHOULD treat the logout request as suspect, and MAY decline to act upon it.
        logout_from_the_op=False,
    ):
        ...

    def delegate(
        self,
        id_token_hint=None,
        logout_hint=None,
        post_logout_redirect_uri=None,
        ui_locales=None,
    ):
        ...

    def authenticate_client(self, request):
        raise NotImplementedError()

    def get_jwks(self):
        raise NotImplementedError()
