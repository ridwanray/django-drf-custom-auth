from django.urls import include, path

from rest_framework.routers import DefaultRouter

from .views import TransactionViewSet

app_name = "transaction"

router = DefaultRouter()
router.register("", TransactionViewSet)

urlpatterns = [
    path("", include(router.urls)),
]
