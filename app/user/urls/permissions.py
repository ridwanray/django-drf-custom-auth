from django.urls import include, path

from rest_framework.routers import DefaultRouter

from ..views import PermissionViewSet

app_name = "permission"

router = DefaultRouter()
router.register("", PermissionViewSet)

urlpatterns = [
    path("", include(router.urls)),
]
