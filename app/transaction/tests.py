import pytest
from django.urls import reverse
from user.permission_list import PERMISSIONS
from user.tests.conftest import api_client_with_credentials

pytestmark = pytest.mark.django_db


class TestTransactions:
    view_transaction_url = reverse("transaction:transaction-list")
    generate_report_url = reverse("transaction:transaction-generate-report")

    def test_generate_report(self, api_client, authenticate_user):
        """User having GenerateReport permission has access"""
        user = authenticate_user(permissions = [PERMISSIONS.GenerateReport,])
        token = user['token']
        api_client_with_credentials(token, api_client)
        response = api_client.get(self.generate_report_url)
        assert response.status_code == 200

    def test_deny_generate_report(self, api_client, authenticate_user):
        """Deny access to user not having  GenerateReport has access"""
        user = authenticate_user(permissions = [PERMISSIONS.ViewTransaction])
        token = user['token']
        api_client_with_credentials(token, api_client)
        response = api_client.get(self.generate_report_url)
        assert response.status_code == 403

    def test_view_transaction(self, api_client, authenticate_user):
        """User having ViewTransaction permission has access"""
        user = authenticate_user(permissions = [PERMISSIONS.ViewTransaction,])
        token = user['token']
        api_client_with_credentials(token, api_client)
        response = api_client.get(self.view_transaction_url)
        assert response.status_code == 200


    def test_deny_view_transaction(self,api_client, authenticate_user):
        user = authenticate_user(permissions = [PERMISSIONS.GenerateReport,])
        token = user['token']
        api_client_with_credentials(token, api_client)
        response = api_client.get(self.view_transaction_url)
        assert response.status_code == 403