from django.contrib import admin
from .models import ScanHistory, ScamNumberCache

admin.site.register(ScanHistory)
admin.site.register(ScamNumberCache)