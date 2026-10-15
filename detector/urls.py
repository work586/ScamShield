
from django.urls import path
from . import views

urlpatterns = [
    # React Dashboard Manual Uploads
    path('api/analyze/', views.analyze_text, name='analyze_text'),
    path('api/voice/', views.analyze_voice, name='analyze_voice'),
    path('api/history/', views.get_history, name='get_history'),

    # Automatic Background Interceptors
    path('api/auto-scan/', views.auto_scan_webhook, name='auto_scan'),
    path('api/sms-webhook/', views.sms_webhook, name='sms_webhook'),
    path('api/call-webhook/', views.call_webhook, name='call_webhook'),

    # Telegram Message Monitoring via MacroDroid
    path('api/telegram-webhook/', views.sms_webhook, name='telegram_webhook'),
]
