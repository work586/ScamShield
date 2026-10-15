import os
import json
import re
import threading
import subprocess

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from rest_framework.parsers import MultiPartParser, FormParser

from .ai_engine import ai
from .models import ScanHistory, ScamNumberCache # Removed ScamWhitelist


# ==========================================
# HELPER FUNCTIONS
# ==========================================
def _clean_identifier(sender):
    """Extracts clean phone number or email to use as a cache key."""
    if not sender or sender.lower() == 'unknown':
        return None
    clean_num = re.sub(r'[^\d]', '', sender)
    if len(clean_num) >= 10:
        return clean_num
    if '@' in sender and '.' in sender:
        return sender.lower().strip()
    return None

def trigger_physical_block():
    """Uses ADB to physically hang up calls and clear notifications."""
    try:
        subprocess.run(['adb', 'shell', 'input', 'keyevent', '5'], timeout=2, capture_output=True)
        subprocess.run(['adb', 'shell', 'cmd', 'notification', 'remove_all'], timeout=2, capture_output=True)
    except Exception:
        pass

def _handle_auto_intercept(text, sender, channel):
    """Core logic for SMS/WhatsApp/Telegram. Silent drop for repeat offenders."""
    identifier = _clean_identifier(sender)
    
    # SILENT DROP IF IN CACHE
    if identifier and ScamNumberCache.objects.filter(identifier=identifier).exists():
        if channel in ('sms', 'voice_call', 'whatsapp', 'telegram'):
            threading.Thread(target=trigger_physical_block).start()
        return {
            "score": 100, "category": "known_scam", "triggers": ["repeat_offender"], 
            "language": "unknown", "channel": channel
        }

    # FIRST TIME OFFENDER: RUN AI & CACHE
    result = ai.analyze_text(text, channel=channel)
    
    ScanHistory.objects.create(
        text=text[:500] if text else f"[INTERCEPTED] Number: {sender}",
        score=result['score'], category=result['category'], channel=channel,
        triggers=result['triggers'], language=result.get('language', 'english'), sender=sender
    )
    
    is_threat = result['score'] >= 30
    if is_threat:
        print(f"🛑 THREAT BLOCKED: {result['category'].upper()} from {sender}")
        if identifier:
            ScamNumberCache.objects.get_or_create(identifier=identifier)
            print(f"🧠 NUMBER CACHED: {sender}")
    else:
        print(f"✅ [{channel.upper()}] Safe message from {sender}")

    return result


# ==========================================
# 1. MANUAL TEXT ANALYSIS
# ==========================================
@csrf_exempt
@api_view(['POST'])
def analyze_text(request):
    try:
        data = request.data
        text = data.get('text', '')
        channel = data.get('channel', 'sms')
        if not text:
            return JsonResponse({"error": "No text provided"}, status=400)
            
        result = ai.analyze_text(text, channel=channel)
        ScanHistory.objects.create(
            text=text[:500], score=result['score'], category=result['category'], 
            channel=channel, triggers=result['triggers'],
            language=result.get('language', 'english'), sender='Manual Upload'
        )
        return JsonResponse(result, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


# ==========================================
# 2. MANUAL VOICE ANALYSIS
# ==========================================
@csrf_exempt
@api_view(['POST'])
def analyze_voice(request):
    try:
        audio_file = request.FILES.get('audio')
        if not audio_file:
            return JsonResponse({"error": "No audio file uploaded"}, status=400)
        temp_path = "temp_audio.wav"
        with open(temp_path, 'wb+') as destination:
            for chunk in audio_file.chunks():
                destination.write(chunk)
                
        result = ai.analyze_voice_call(temp_path)
        
        if 'error' not in result:
            ScanHistory.objects.create(
                text="[VOICE CALL]", 
                score=result.get('score', 0), category=result.get('category', 'safe'), 
                channel='voice', triggers=result.get('triggers', []),
                language=result.get('language', 'english'),
                transcript=result.get('transcript', ''), sender='Manual Voice Upload'
            )
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return JsonResponse(result, status=200)
    except Exception as e:
        if 'temp_audio.wav' in str(e) and os.path.exists("temp_audio.wav"):
            os.remove("temp_audio.wav")
        return JsonResponse({"error": str(e)}, status=500)


# ==========================================
# 3. GET HISTORY
# ==========================================
@csrf_exempt
@api_view(['GET'])
def get_history(request):
    try:
        history = ScanHistory.objects.all().order_by('-id')[:]
        data = list(history.values(
            'id', 'text', 'score', 'category', 'channel', 
            'triggers', 'language', 'time', 'sender', 'transcript'
        ))
        return JsonResponse(data, safe=False, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


# ==========================================
# 4. AUTOMATIC EMAIL WEBHOOK
# ==========================================

# ==========================================
# AUTOMATIC EMAIL / GMAIL WEBHOOK
# ==========================================
@csrf_exempt
@api_view(['POST'])
def auto_scan_webhook(request):
    try:
        data = request.data

        text = str(data.get('text') or data.get('message') or '').strip()
        sender = str(data.get('sender') or 'Unknown').strip()
        source_channel = str(data.get('channel') or 'email').strip().lower()

        if not text:
            return JsonResponse(
                {"error": "No email notification text provided"},
                status=400
            )

        # Prevent this endpoint from accidentally recording
        # Gmail scans under another channel.
        source_channel = 'email'

        result = _handle_auto_intercept(
            text=text,
            sender=sender,
            channel=source_channel
        )

        return JsonResponse({
            "status": "auto_scanned",
            "channel": "email",
            "sender": sender,
            "is_threat": result.get('score', 0) >= 30,
            "result": result
        }, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)



# ==========================================
# 5. UNIVERSAL SMS/TELEGRAM/WHATSAPP WEBHOOK
# ==========================================
@csrf_exempt
def sms_webhook(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    sender_number = "Unknown"
    message_body = ""
    source_channel = "sms"

    try:
        data = json.loads(request.body.decode("utf-8"))
        sender_number = data.get("sender") or data.get("sms_number") or "Unknown"
        message_body = data.get("text") or data.get("message") or ""
        if data.get("channel"): source_channel = data.get("channel")
    except:
        sender_number = request.POST.get("sender") or request.POST.get("sms_number") or "Unknown"
        message_body = request.POST.get("text") or request.POST.get("message") or ""
        if request.POST.get("channel"): source_channel = request.POST.get("channel")

    if not message_body or not message_body.strip():
        return JsonResponse({"error": "No message provided"}, status=400)

    result = _handle_auto_intercept(message_body.strip(), sender_number, source_channel)
    return JsonResponse(result, status=200)


# ==========================================
# 6. AUTOMATIC CALL WEBHOOK (RE-CACH BUG FIXED)
# ==========================================
@csrf_exempt
def call_webhook(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8"))
    except:
        data = request.POST

    phone_number = data.get("number", "Unknown")
    identifier = _clean_identifier(phone_number)
    
    # SILENT DROP IF IN CACHE (No re-caching bug!)
    if identifier and ScamNumberCache.objects.filter(identifier=identifier).exists():
        threading.Thread(target=trigger_physical_block).start()
        return JsonResponse({
            "score": 100, "category": "known_scam", "triggers": ["repeat_offender"], 
            "alert_message": ""
        }, status=200)

    # FIRST TIME CALLER: PATTERN MATCHING
    score = 0
    triggers = []
    category = "safe"
    num_str = str(phone_number).replace(" ", "").replace("-", "")

    if num_str.startswith('+') and not num_str.startswith('+91'):
        score += 45
        triggers.append('international_scam')
    if len(num_str) <= 5 and num_str.isdigit():
        score += 50
        triggers.append('premium_scam')
    if num_str.startswith('+91') and len(num_str) == 13 and num_str[3:].startswith('140'):
        score += 40
        triggers.append('telemarketer_scam')

    score = max(0, min(100, score))
    
    if triggers:
        category = triggers[0]
        score = max(score, 35)
        
        print(f"📞 [CALL] SCAM BLOCKED: {phone_number} - Category: {category}")
        
        ScanHistory.objects.create(
            text=f"[CALL DETECTED] Number: {phone_number}",
            score=score, category=category, channel='voice_call',
            triggers=triggers, language='unknown', sender=phone_number
        )
        
        # ONLY cache if not already in cache (Fixes the override bug)
        if identifier and not ScamNumberCache.objects.filter(identifier=identifier).exists():
            ScamNumberCache.objects.create(identifier=identifier)
            print(f"🧠 NUMBER CACHED: {phone_number}")
    else:
        print(f"📞 [CALL] Safe number: {phone_number}")
        ScanHistory.objects.create(
            text=f"[CALL DETECTED] Number: {phone_number}",
            score=score, category=category, channel='voice_call',
            triggers=triggers, language='unknown', sender=phone_number
        )

    return JsonResponse({
        "score": score,
        "category": category,
        "triggers": triggers, 
        "alert_message": "Scam Detected!" if score >= 30 else "Number looks safe."
    }, status=200)