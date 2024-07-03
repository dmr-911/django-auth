import jwt, datetime
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication
from .models import User
from rest_framework.authentication import get_authorization_header


# Middleware
class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request): #over write the authenticate function
        auth = get_authorization_header(request).split()
        if auth and len(auth) == 2:
            token = auth[1].decode("utf-8")
            id = decode_token(token)
            user = User.objects.get(id=id)
            return (user, None)  # to make it iterable

        # return Response(auth)
        raise exceptions.AuthenticationFailed("Authentication failed")


def create_access_token(id):
    return jwt.encode(
        {
            "user_id": id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=4),
            "iat": datetime.datetime.utcnow(),
        },
        "access_secret",
        algorithm="HS256",
    )


def create_refresh_token(id):
    return jwt.encode(
        {
            "user_id": id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
            "iat": datetime.datetime.utcnow(),
        },
        "refresh_secret",
        algorithm="HS256",
    )


def decode_token(token):
    try:
        payload = jwt.decode(token, "access_secret", algorithms="HS256")
        return payload["user_id"]
    except:
        raise exceptions.AuthenticationFailed("Unuthenticated User")


def decode_refresh_token(token):
    try:
        payload = jwt.decode(token, "refresh_secret", algorithms="HS256")
        return payload["user_id"]
    except:
        raise exceptions.AuthenticationFailed("Unuthenticated User")