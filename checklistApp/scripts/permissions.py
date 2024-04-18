from rest_framework import permissions
from checklistApp.serializers import UserSerializer
from checklistApp.models import User


# class isAdminOrReadOnly(permissions.BasePermission):
#     def has_object_permission(self, request, view, obj):
#             # Read permissions are allowed to any request,
#             # so we'll always allow GET, HEAD or OPTIONS requests.
#             if request.method in permissions.SAFE_METHODS:
#                 user_role =  User.objects.get('role')
#                 if user_role == 'admin':
#                     return True

#             # Write permissions are only allowed to the owner of the snippet.
#             return obj.admin == request.user

class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        user_email = request.user
        try:
            user = User.objects.get(email=user_email)
        except User.DoesNotExist():
            return False
        if user.role in ["Admin", "admin"] and request.user.is_authenticated == True:
        # if user.role in "admin" and request.user.is_authenticated == True:
            return True
        return False

# from rest_framework import permissions

# class IsAdmin(permissions.BasePermission):
#     def has_permission(self, request, view):
#         if request.user.is_authenticated and request.user.email == "cdacadmin@gmail.com":
#             return True
#         return False

    
class IsReviewer(permissions.BasePermission):
    def has_permission(self, request, view):
        user_email = request.user
        try:
            user = User.objects.get(email=user_email)
        except User.DoesNotExist():
            return False
        if user.role in ["Reviewer", "reviewer"] and request.user.is_authenticated == True:
            return True
        return False