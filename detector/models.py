from django.db import models
from django.db.models.signals import post_delete
from django.dispatch import receiver

class ScanHistory(models.Model):
    text = models.TextField()
    score = models.IntegerField(default=0)
    category = models.CharField(max_length=50, default='safe')
    channel = models.CharField(max_length=20, default='sms')
    triggers = models.JSONField(default=list, blank=True)
    language = models.CharField(max_length=20, default='english')
    sender = models.CharField(max_length=255, blank=True, default='Manual Upload')
    transcript = models.TextField(blank=True, default='')
    time = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-time']

    def __str__(self):
        return f"[{self.channel}] {self.category} - {self.score}"

class ScamNumberCache(models.Model):
    identifier = models.CharField(max_length=255, unique=True)
    blocked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Scam Cache"
        verbose_name_plural = "Scam Caches"

    def __str__(self):
        return self.identifier

class ScamWhitelist(models.Model):
    """
    Numbers/Emails manually unblocked by the user. 
    They will bypass the cache AND call pattern matching completely.
    """
    identifier = models.CharField(max_length=255, unique=True)
    whitelisted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Whitelist"
        verbose_name_plural = "Whitelist"

    def __str__(self):
        return self.identifier


# ==========================================
# AUTO-WHITELIST SIGNAL
# ==========================================
# When you delete a number from Scam Cache, it automatically gets 
# added to the Whitelist so it is permanently unblocked.
@receiver(post_delete, sender=ScamNumberCache)
def add_to_whitelist_on_cache_delete(sender, instance, **kwargs):
    ScamWhitelist.objects.get_or_create(identifier=instance.identifier)