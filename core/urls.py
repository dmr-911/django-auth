from django.contrib import admin
from django.urls import path, include
from .views import (
    RegisterAPIView,
    LoginAPIView,
    UserAPIView,
    RefreshAPIView,
    LogoutAPIView,
    ForgotAPIView,
    ResetAPIView,
    # `TwoFactorLoginAPIView` appears to be a view for handling two-factor authentication (2FA) during
    # the login process. It is likely used to verify the user's identity using an additional factor
    # beyond just the username and password, such as a code sent to their phone or email. This extra
    # layer of security helps protect user accounts from unauthorized access.
    TwoFactorLoginAPIView,
)

urlpatterns = [
    path("register/", RegisterAPIView.as_view()),
    path("login/", LoginAPIView.as_view()),
    path("tfa/", TwoFactorLoginAPIView.as_view()),
    path("user/", UserAPIView.as_view()),
    path("refresh/", RefreshAPIView.as_view()),
    path("logout/", LogoutAPIView.as_view()),
    path("forget/", ForgotAPIView.as_view()),
    path("reset/", ResetAPIView.as_view()),
]
