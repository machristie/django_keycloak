import json
import logging
import time

import requests
from django.conf import settings
from django.contrib.auth.models import User
from django.urls import reverse
from requests_oauthlib import OAuth2Session

logger = logging.getLogger(__name__)


class KeycloakBackend(object):
    """Django authentication backend for Keycloak."""

    def authenticate(self, request=None, username=None, password=None):
        try:
            token, userinfo = self._get_token_and_userinfo_redirect_flow(
                request)
            self._process_token(request, token)
            return self._process_userinfo(request, userinfo)
        except Exception as e:
            logger.exception("login failed", exc_info=e)
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def _get_token_and_userinfo_redirect_flow(self, request):
        authorization_code_url = request.build_absolute_uri()
        client_id = settings.KEYCLOAK_CLIENT_ID
        client_secret = settings.KEYCLOAK_CLIENT_SECRET
        token_url = settings.KEYCLOAK_TOKEN_URL
        userinfo_url = settings.KEYCLOAK_USERINFO_URL
        state = request.session['OAUTH2_STATE']
        redirect_uri = request.session['OAUTH2_REDIRECT_URI']
        oauth2_session = OAuth2Session(client_id,
                                       scope='openid email profile',
                                       redirect_uri=redirect_uri,
                                       state=state)
        token = oauth2_session.fetch_token(
            token_url, client_secret=client_secret,
            authorization_response=authorization_code_url)
        userinfo = oauth2_session.get(userinfo_url).json()
        return token, userinfo

    def _process_token(self, request, token):
        # TODO validate the JWS signature
        logger.debug(
            "token: {}".format(
                json.dumps(
                    token,
                    indent=True,
                    sort_keys=True)))
        now = time.time()
        # Put access_token into session to be used for authenticating with API
        # server
        sess = request.session
        sess['ACCESS_TOKEN'] = token['access_token']
        sess['ACCESS_TOKEN_EXPIRES_AT'] = now + token['expires_in']
        sess['REFRESH_TOKEN'] = token['refresh_token']
        sess['REFRESH_TOKEN_EXPIRES_AT'] = now + token['refresh_expires_in']

    def _process_userinfo(self, request, userinfo):
        logger.debug(
            "userinfo: {}".format(
                json.dumps(
                    userinfo,
                    indent=True,
                    sort_keys=True)))
        username = userinfo['preferred_username']
        email = userinfo['email']
        first_name = userinfo['given_name']
        last_name = userinfo['family_name']
        request.session['USERINFO'] = userinfo
        try:
            user = User.objects.get(username=username)
            # Update these fields each time, in case they have changed
            user.email = email
            user.first_name = first_name
            user.last_name = last_name
            user.save()
            return user
        except User.DoesNotExist:
            user = User(username=username,
                        first_name=first_name,
                        last_name=last_name,
                        email=email)
            user.save()
            return user
