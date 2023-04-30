from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from user.permission_list import PERMISSIONS
from user.permissions import CustomPermissionMixin

from .models import Transaction
from .serializers import TransactionSerializer


class TransactionViewSet(CustomPermissionMixin,viewsets.ModelViewSet):
    queryset = Transaction.objects.all()
    pagination_class = None
    http_method_names = ["get"]
    serializer_class = TransactionSerializer

    custom_permissions = [
        PERMISSIONS.ViewTransaction,
        PERMISSIONS.GenerateReport,
    ]

    def get_custom_permissions(self):
        permission_classes = self.custom_permissions
        if self.action in ['list']:
            permission_classes = [PERMISSIONS.ViewTransaction]
        if self.action in ['generate_report']:
            permission_classes = [PERMISSIONS.GenerateReport]
        return permission_classes


    def list(self, request, *args, **kwargs):
        """View Transactions"""
        return super().list(request, *args, **kwargs)

    @action(methods=['GET'], detail=False, url_path='generate-report')
    def generate_report(self, request, pk=None):
        """ generate report """
        return Response({"success": True, "message": "Report generated successfully"}, status=200)