import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings.dev")
import django
django.setup()

from user.tests.factories import TransactionFactory

TransactionFactory.create_batch(10)