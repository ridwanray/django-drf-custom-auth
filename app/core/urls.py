from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

urlpatterns = [
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/v1/doc/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/v1/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    path('api/v1/auth/', include('user.urls.auth')),
    path('api/v1/user/', include('user.urls.user')),
    path('api/v1/roles/', include('user.urls.roles')), 
    path('api/v1/permissions/', include('user.urls.permissions')), 
    path('api/v1/transactions/', include('transaction.urls')), 
]