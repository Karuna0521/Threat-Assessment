import json
import jwt
from django.conf import settings
from rest_framework import exceptions
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError, AuthenticationFailed
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.backends import TokenBackend
# from amshome.mixin import data_encrypt
from checklistApp.models import User
from cdacProject.settings import VERIFYING_KEY

# class MyJWTAuthentication(JWTAuthentication):
    
#     def get_validated_token(self, raw_token):
#         token=raw_token.decode("utf-8")
#         print("This is token --------> ",token)
#         options = {
#             'verify_exp': True,
#             'verify_aud': False
#         }
#         try:
#             valid_data = jwt.decode(token, VERIFYING_KEY, algorithms=['RS256'],options=options,verify=True)
#             print("This is valid_data-->", valid_data)
#             return token
#         except Exception as e:
#             print(e)

#     def authenticate(self, request):

#         header = self.get_header(request)
#         if header is None:
#             return None

#         raw_token = self.get_raw_token(header)
        
#         if raw_token is None:
#             return None

#         validated_token = self.get_validated_token(raw_token)
#         print("decoded header :- ",self.get_header(request).decode())

#         options = {
#             'verify_exp': False,
#             'verify_aud': False
#         }
#         try:
#             key= VERIFYING_KEY
#             # key= "-----BEGIN PUBLIC KEY-----\n" + request.headers["X-Public-Key"] + "\n-----END PUBLIC KEY-----"

#             # print("public key---------->>>>>>>> : ",key)
#             valid_data = jwt.decode(validated_token, key=VERIFYING_KEY, algorithms=['RS256'],options=options)
#             print(valid_data)
#             # user = valid_data['email']

#             try:
#                 # print(user)
#                 # decode_user = data_encrypt(email=user)
#                 checkappuser = User.objects.get(id=valid_data["user_id"])
#                 print("--------->>>>user", type(checkappuser))
#             except User.DoesNotExist:
#                 raise AuthenticationFailed(('User not found'),code='user_not_found')

#             if not checkappuser.is_active:
#                 raise AuthenticationFailed(('User is inactive'),code='user_inactive')
#             # checkappuser.is_authenticated = True
#             return (checkappuser, None)

#         except Exception as e:
#             print("exception", e)

class MyJWTAuthentication(JWTAuthentication):
    
    def get_validated_token(self, raw_token):
        try:
            token = raw_token.decode("utf-8")
            options = {
                'verify_exp': True,
                'verify_aud': False
            }
            valid_data = jwt.decode(token, VERIFYING_KEY, algorithms=['RS256'], options=options, verify=True)
            return token, valid_data
        except Exception as e:
            raise AuthenticationFailed('Token validation failed')

    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        try:
            validated_token, valid_data = self.get_validated_token(raw_token)

            options = {
                'verify_exp': False,
                'verify_aud': False
            }

            try:
                key = VERIFYING_KEY
                valid_data = jwt.decode(validated_token, key=key, algorithms=['RS256'], options=options)
                user_id = valid_data.get("user_id")

                if user_id is not None:
                    try:
                        checkappuser = User.objects.get(id=user_id)
                    except User.DoesNotExist:
                        raise AuthenticationFailed('User not found', code='user_not_found')

                    if not checkappuser.is_active:
                        raise AuthenticationFailed('User is inactive', code='user_inactive')

                    return checkappuser, None
                else:
                    raise AuthenticationFailed('User ID not present in token', code='user_id_missing')

            except jwt.ExpiredSignatureError:
                raise AuthenticationFailed('Token has expired', code='token_expired')
            except jwt.DecodeError:
                raise AuthenticationFailed('Token is invalid', code='token_invalid')
            except jwt.InvalidTokenError:
                raise AuthenticationFailed('Invalid token', code='invalid_token')
        except AuthenticationFailed as e:
            raise e  # Reraise the AuthenticationFailed exception



class InvalidToken(Exception):
    pass