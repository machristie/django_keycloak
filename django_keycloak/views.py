
import logging
from urllib.parse import quote

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from requests_oauthlib import OAuth2Session

logger = logging.getLogger(__name__)


def redirect_login(request):
    client_id = settings.KEYCLOAK_CLIENT_ID
    base_authorize_url = settings.KEYCLOAK_AUTHORIZE_URL
    redirect_uri = request.build_absolute_uri(reverse('callback'))
    if 'next' in request.GET:
        redirect_uri += "?next=" + quote(request.GET['next'])
    oauth2_session = OAuth2Session(
        client_id, scope='openid email profile', redirect_uri=redirect_uri)
    authorization_url, state = oauth2_session.authorization_url(
        base_authorize_url)
    # Store state in session for later validation (see auth.py)
    request.session['OAUTH2_STATE'] = state
    request.session['OAUTH2_REDIRECT_URI'] = redirect_uri
    return redirect(authorization_url)


def callback(request):
    try:
        user = authenticate(request=request)
        login(request, user)
        next_url = request.GET.get('next', settings.LOGIN_REDIRECT_URL)
        return redirect(next_url)
    except Exception as err:
        logger.exception("An error occurred while processing OAuth2 "
                         "callback: {}".format(request.build_absolute_uri()))
        raise err


@login_required
def protected(request):
    return HttpResponse("Protected resource")
