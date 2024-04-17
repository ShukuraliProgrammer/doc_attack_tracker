from django.db import models


# Create your models here.
class BlackIps(models.Model):
    ip = models.CharField(max_length=15, unique=True)
    reason = models.CharField(max_length=255)
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    request_count = models.IntegerField(default=0)
    def __str__(self):
        return self.ip

