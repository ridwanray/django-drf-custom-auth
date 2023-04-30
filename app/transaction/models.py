from core.models import AuditableModel
from django.db import models


class Transaction(AuditableModel):
    amount = models.DecimalField(max_digits=8, decimal_places=2)
    date =  models.DateTimeField(auto_now_add=True)