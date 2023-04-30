from datetime import datetime, timezone
from typing import Any, Dict

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.utils.crypto import get_random_string
from rest_framework import permissions

from .enums import SystemRoleEnum
from .models import Token, User


def send_email(subject:str, email_to: str, html_alternative: Any, attachment: Dict = None):
    msg = EmailMultiAlternatives(
        subject=subject, from_email=settings.EMAIL_FROM,to= [email_to]
    )
    msg.attach_alternative(html_alternative, "text/html")
    msg.send(fail_silently=False)


def create_token_and_send_user_email(user: User, token_type: str)->None:
    from .tasks import send_user_creation_email
    token, _ = Token.objects.update_or_create(
        user=user,
        token_type=token_type,
        defaults={
            "user": user,
            "token_type": token_type,
            "token": get_random_string(120),
            "created_at": datetime.now(timezone.utc)
        },
    )
    user_data = {
        "email": user.email,
        "fullname": f"{user.firstname}",
        "token": token.token
    }
    send_user_creation_email.delay(user_data)


def get_user_role_names(user:User)->list:
    """
    Returns a list of role names for the given user.
    """
    return user.roles.values_list('name', flat=True)

def is_admin_user(user:User)->bool:
    """
    Check an authenticated user is an admin or not
    """
    return user.is_admin or user.roles.filter(name=SystemRoleEnum.SUPERADMIN).exists() 


class IsAdmin(permissions.BasePermission):
    """Allows access only to Admin users."""
    message = "Only Admins are authorized to perform this action."
    
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        return  is_admin_user(request.user)
    
