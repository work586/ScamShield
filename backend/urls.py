
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # THIS LINE IS REQUIRED FOR THE 404 TO GO AWAY:
    path('', include('detector.urls')), 
]