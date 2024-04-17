from django.db import models


# Create your models here.
class BlackIps(models.Model):
    ip = models.CharField(max_length=15)
    reason = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip

