import factory
from django.contrib.auth.models import User
from faker import Faker

from user.models import Token, User, Permission, Role

fake = Faker()

class UserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = User
        
    email = factory.Sequence(lambda n: 'person{}@example.com'.format(n))
    password = factory.PostGenerationMethodCall('set_password','passer@@@111')
    verified='True'
    firstname = fake.name()
    lastname = fake.name()
    
       
class SuperAdminUserFactory(UserFactory):
    """"Factory for a super admin user"""
    verified = 'True'
    is_superuser = 'True'

class TokenFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Token
    token = fake.md5()

class TokenFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Token
    token = fake.md5()


class PermissionFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Permission
    
    name = factory.Sequence(lambda n: 'permission{}'.format(n))


class RoleFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Role
    
    name = fake.name()

    @factory.post_generation
    def permissions(self, create, extracted, **kwargs):
        if not create:
            return
        if extracted:
            
            role_permissions = [PermissionFactory(name = each) for each in extracted ]
            self.permissions.set(role_permissions)