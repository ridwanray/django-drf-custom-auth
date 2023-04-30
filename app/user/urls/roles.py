from django.urls import include, path

from rest_framework.routers import DefaultRouter

from ..views import RoleViewSet

app_name = "role"

router = DefaultRouter()
router.register("", RoleViewSet)

urlpatterns = [
    path("", include(router.urls)),
]
