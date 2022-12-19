from django.urls import path, include
from .views import create_password, personal_account, create_master_password, type_master_password

urlpatterns = [
    path('', include('accounts.urls')),
    path('', create_password, name='home'),
    path('create/', create_master_password, name='master'),
    path('access_vault/', type_master_password, name='type_master'),
    path('account/', personal_account, name='account'),
]