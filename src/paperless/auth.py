import json

import jwt
import requests
from django.conf import settings
from django.contrib import auth
from django.contrib.auth.middleware import PersistentRemoteUserMiddleware
from django.contrib.auth.models import User
from django.utils.deprecation import MiddlewareMixin
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed


class AutoLoginMiddleware(MiddlewareMixin):
    def process_request(self, request):
        try:
            request.user = User.objects.get(username=settings.AUTO_LOGIN_USERNAME)
            auth.login(
                request=request,
                user=request.user,
                backend="django.contrib.auth.backends.ModelBackend",
            )
        except User.DoesNotExist:
            pass


class AngularApiAuthenticationOverride(authentication.BaseAuthentication):
    """This class is here to provide authentication to the angular dev server
    during development. This is disabled in production.
    """

    def authenticate(self, request):
        if (
            settings.DEBUG
            and "Referer" in request.headers
            and request.headers["Referer"].startswith("http://localhost:4200/")
        ):
            user = User.objects.filter(is_staff=True).first()
            print(f"Auto-Login with user {user}")
            return (user, None)
        else:
            return None


class HttpRemoteUserMiddleware(PersistentRemoteUserMiddleware):
    """This class allows authentication via HTTP_REMOTE_USER which is set for
    example by certain SSO applications.
    """

    header = settings.HTTP_REMOTE_USER_HEADER_NAME


class CloudflareAccessAuthentication(authentication.BaseAuthentication):
    """This class allows authentication via Cloudflare Access."""

    def _get_public_keys(self):
        """Returns the signing public key for the application token."""
        res = requests.get(
            f"https://{settings.CLOUDFLARE_TEAM_NAME}.cloudflareaccess.com/cdn-cgi/access/certs",
        )
        public_keys = []
        jwk_set = res.json()
        for key_dict in jwk_set["keys"]:
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_dict))
            public_keys.append(public_key)
        return public_keys

    def authenticate(self, request):
        # Immediately return if CLOUDFLARE_TEAM_NAME or CLOUDFLARE_AUD_TAG is not set
        if not settings.CLOUDFLARE_TEAM_NAME or not settings.CLOUDFLARE_AUD_TAG:
            print("Cloudflare Access authentication is not configured.")
            return None
        print(f"Team name: {settings.CLOUDFLARE_TEAM_NAME}")
        print(f"Audience tag: {settings.CLOUDFLARE_AUD_TAG}")

        # Check for Cf-Access-Jwt-Assertion header or CF_Authorization cookie
        if "HTTP_CF_ACCESS_JWT_ASSERTION" in request.META:
            cf_application_token = request.META.get("HTTP_CF_ACCESS_JWT_ASSERTION")
        elif "CF_Authorization" in request.COOKIES:
            cf_application_token = request.COOKIES.get("CF_Authorization")
        else:
            return None

        # Get public keys from Cloudflare
        keys = self._get_public_keys()

        # Loop through the keys since we can't pass the key set to the decoder
        payload = None
        for key in keys:
            try:
                # decode returns the claims that has the email when needed
                payload = jwt.decode(
                    cf_application_token,
                    key=key,
                    audience=settings.CLOUDFLARE_AUD_TAG,
                    algorithms=["RS256"],
                )
                break
            except jwt.InvalidTokenError:
                pass
        if payload is None:
            raise AuthenticationFailed

        # Check if the user exists, if not create it
        try:
            user = User.objects.get(email=payload["email"])
        except User.DoesNotExist:
            user = User.objects.create_user(
                payload["custom"]["preferred_username"],
                email=payload["email"],
            )
            user.save()

        return (user, None)
