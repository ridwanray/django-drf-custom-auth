from functools import wraps
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from .models import Permission, User


def get_user_permissions(user: User):
    """
    Retrieve a user's permissions
    """
    if user.is_authenticated:
        return list(Permission.objects.filter(
            role__id__in=user.roles.values_list("id", flat=True)
        ).values_list("name", flat=True))
    raise AuthenticationFailed


def check_user_has_permissions(user:User, required_perms:list):
    user_permissions = get_user_permissions(user)

    def check_perm(user_perm_list):
        return any(_perm in user_perm_list for _perm in required_perms)

    if user.is_admin is False and required_perms and check_perm(user_permissions) is False:
        raise PermissionDenied


def permission_checker(perm):
    """
    Custom permission checker decorator.
    """

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(cls, request, *args, **kwargs):
            perms = [perm] if isinstance(perm, str) else perm
            user = request.user
            check_user_has_permissions(user, perms)
            return view_func(cls, request, *args, **kwargs)

        return wrapper

    return decorator


class CustomPermissionMixin:
    """
    Custom Permission mixin
    """
    custom_permissions = None

    def check_permissions(self, request):
        check_user_has_permissions(request.user, self.get_custom_permissions())
        return super().check_permissions(request)

    def get_custom_permissions(self):
        return self.custom_permissions
