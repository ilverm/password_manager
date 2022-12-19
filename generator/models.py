from django.db import models
from django.conf import settings

# Create your models here.
class StorePassword(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    website = models.TextField(null=False)
    username = models.TextField(unique=True)
    password = models.BinaryField(null=False)

    def __str__(self):
        return self.website

class GeneralPassword(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    salt = models.BinaryField(null=False)
    key = models.BinaryField(null=False)