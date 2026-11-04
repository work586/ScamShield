"""
ScamShield AI Engine  (v2)
==========================
Multilingual scam detection for English, Hindi, Hinglish, and Kannada.
Supports: SMS, Email, WhatsApp, Telegram, Voice channels.

BACKWARD COMPATIBLE
-------------------
Public interface is unchanged:
    ai.analyze_text(text, channel='sms')      -> dict
    ai.analyze_voice_call(audio_path)         -> dict
    ai.detect_language(text), ai.preprocess_text(text)
    is_legit_otp_pattern(text_lower)
    ai  (module-level singleton)

The result dict still has: score, category, triggers, language, channel
and now ALSO: risk_level, confidence, reasons, advice, sub_categories.
`category` / `triggers` only use the original category names unless you
create ScamShieldAI(expose_new_categories=True).

WHAT CHANGED vs v1
------------------
 1. Keyword matching uses word boundaries for Latin text ('ed' no longer
    matches "need", 'hi' no longer matches "this", 'won' not "won't").
    Indic text uses plain substring matching (agglutinative scripts).
 2. OTP: detects a *request* to share OTP/PIN/password with negation
    handling, so "Do not share your OTP" is no longer flagged.
 3. Scoring is signal based. The old "any trigger => score >= 35" floor is
    gone; weak single signals stay below the threshold, combinations
    (brand/authority + urgency + action) go above it.
 4. Legit bank transaction alerts ("Rs 500 debited ... call 1800...") are
    not flagged; fake ones that ask you to call a mobile number or click
    a link are.
 5. Input normalisation: NFKC, zero-width characters, Indic digits,
    look-alike letters and "O T P" / "0TP" obfuscation.
 6. Better URL analysis via urlparse: high-risk TLDs, shorteners, IP
    hosts, punycode, '@' tricks, .apk links, brand-in-domain spoofing
    (official domains whitelisted), bare domains without http.
 7. Indian phone-number handling (+91, spaces, toll-free 1800/1860).
 8. New scam types: digital arrest, fake courier, electricity
    disconnection, UPI refund/QR, remote-access apps, SIM/Aadhaar/PAN KYC,
    loan apps, sextortion, task/like-and-earn scams.
 9. Optional `sender` argument (mobile number "bank" => suspicious).
10. Language detection: ambiguous English words removed from Hinglish
    markers, other Indian scripts recognised.
11. Voice: no shared temp file (thread/process safe), no clipped speech,
    optional faster-whisper, best-of-three Google fallback.
12. Model loading: optional SHA-256 check for the pickle files.
13. Keyword lists can be extended without code changes via keywords.json.
"""

import hashlib
import json
import logging
import os
import pickle
import re
import tempfile
import unicodedata
from urllib.parse import urlparse

log = logging.getLogger('scamshield')

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))


# ==========================================
# TEXT NORMALISATION
# ==========================================
def _build_translation_table():
    table = {}
    # zero-width / invisible characters (also removes ZWNJ/ZWJ in Indic text)
    for ch in '\u200b\u200c\u200d\u2060\ufeff\u00ad\u200e\u200f':
        table[ord(ch)] = None
    # Indic digits -> ASCII digits
    for base in (0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6, 0x0D66):
        for i in range(10):
            table[base + i] = ord('0') + i
    # Cyrillic/Greek look-alikes -> Latin
    for src, dst in zip('аеорсхуіѕјοϲ', 'aeopcxyisjoc'):
        table[ord(src)] = dst
    return table


_TRANSLATION = _build_translation_table()
_OTP_OBFUSCATED = re.compile(r'\bo[\s.\-_*]{0,2}t[\s.\-_*]{0,2}p\b')
_ZERO_TP = re.compile(r'\b0tp\b')


def normalize_text(text):
    """NFKC + invisible chars + Indic digits + look-alikes + lowercase."""
    text = unicodedata.normalize('NFKC', text)
    text = text.translate(_TRANSLATION).lower()
    text = _OTP_OBFUSCATED.sub('otp', text)
    text = _ZERO_TP.sub('otp', text)
    return re.sub(r'\s+', ' ', text).strip()


def build_matcher(phrases):
    """
    Compile a list of phrases into ONE regex.
      - Latin phrases : matched with word boundaries (no substring false positives)
      - Indic phrases : matched as substrings (\\b is unreliable with matras)
      - 're:<regex>'  : inserted as a raw regex
    Phrases are normalised the same way as the input text.
    """
    latin, indic, raw, seen = [], [], [], set()
    for p in phrases:
        if p.startswith('re:'):
            raw.append('(?:' + p[3:] + ')')
            continue
        p = normalize_text(p)
        if not p or p in seen:
            continue
        seen.add(p)
        body = r'\s+'.join(re.escape(x) for x in p.split())
        (latin if p.isascii() else indic).append((len(p), body))
    parts = []
    if latin:
        alt = '|'.join(b for _, b in sorted(latin, reverse=True))
        parts.append(r'(?<![a-z0-9])(?:' + alt + r')(?![a-z0-9])')
    if indic:
        alt = '|'.join(b for _, b in sorted(indic, reverse=True))
        parts.append('(?:' + alt + ')')
    parts += raw
    return re.compile('|'.join(parts)) if parts else None


def _search(matcher, text):
    """Return the matched text or None."""
    if matcher is None:
        return None
    m = matcher.search(text)
    return m.group(0) if m else None


# ==========================================
# OTP FALSE-POSITIVE FIX  (kept for compatibility)
# ==========================================
def is_legit_otp_pattern(text_lower):
    """
    Detects genuine OTP messages. Returns True only if the message looks like
    an OTP AND has no scam red flags (link click, call-back number, ask to
    share with an executive).
    """
    otp_patterns = [
        # English
        r'\botp\b.{0,20}\d{4,6}',
        r'\d{4,6}.{0,20}\botp\b',
        r'\bcode\b.{0,15}\d{4,6}',
        r'is your otp',
        r'otp for txn',
        r'otp for transaction',
        r'do not share.{0,30}otp',
        r'valid for \d+ min',
        r'validity \d+ min',
        # Hindi
        r'ओटीपी.{0,20}\d{4,6}',
        r'\d{4,6}.{0,20}ओटीपी',
        r'साझा न करें',
        r'शेयर न करें',
        r'मिनट.{0,10}वैध',
        r'वैध.{0,10}मिनट',
        # Hinglish
        r'otp hai \d{4,6}',
        r'\d{4,6} otp hai',
        r'share mat karo',
        r'kisi ko share mat karo',
        r'min valid hai',
        r'valid hai \d+ min',
        # Kannada
        r'ಒಟಿಪಿ.{0,20}\d{4,6}',
        r'\d{4,6}.{0,20}ಒಟಿಪಿ',
        r'ಹಂಚಿಕೊಳ್ಳಬೇಡಿ',
        r'ಹಂಚಿಕೊಳ್ಳಲು ಬೇಡಿ',
        r'ನಿಮಿಷ.{0,10}ಮಾನ್ಯ',
        r'ಮಾನ್ಯ.{0,10}ನಿಮಿಷ',
    ]

    scam_override_patterns = [
        # English
        r'click.{0,15}(link|http)',
        r'call.{0,15}\d{8,10}',
        r'verify.{0,15}(account|kyc).{0,15}(link|click)',
        r'share.{0,15}otp.{0,15}(executive|agent|manager)',
        # Hindi
        r'क्लिक.{0,15}(लिंक|http)',
        r'कॉल.{0,15}\d{8,10}',
        r'साझा करें.{0,15}ओटीपी',
        # Hinglish
        r'click karo.{0,15}(link|http)',
        r'call karo.{0,15}\d{8,10}',
        r'share karo.{0,15}otp',
        # Kannada
        r'ಕ್ಲಿಕ್.{0,15}(ಲಿಂಕ್|http)',
        r'ಕರೆ ಮಾಡಿ.{0,15}\d{8,10}',
        r'ಹಂಚಿಕೊಳ್ಳಿ.{0,15}ಒಟಿಪಿ',
    ]

    has_otp_shape = any(re.search(p, text_lower) for p in otp_patterns)
    has_scam_flag = any(re.search(p, text_lower) for p in scam_override_patterns)
    return has_otp_shape and not has_scam_flag


# ==========================================
# OPTIONAL SAFE MODEL LOADING
# ==========================================
def _resolve_path(path):
    if os.path.exists(path):
        return path
    alt = os.path.join(MODULE_DIR, os.path.basename(path))
    return alt if os.path.exists(alt) else path


def _load_pickle(path):
    """
    Loads a pickle. If '<path>.sha256' exists the file hash must match,
    otherwise the file is refused (pickle can execute code when loaded).
    Create it with:  sha256sum model.pkl > model.pkl.sha256
    """
    sha_path = path + '.sha256'
    if os.path.exists(sha_path):
        with open(sha_path, 'r') as f:
            expected = f.read().split()[0].strip().lower()
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        if h.hexdigest() != expected:
            raise ValueError('checksum mismatch for %s' % path)
    with open(path, 'rb') as f:
        return pickle.load(f)


# ==========================================
# MAIN AI ENGINE CLASS
# ==========================================
class ScamShieldAI:
    """
    Multilingual scam detection pipeline.
    Scoring: 0-100. >= SUSPICIOUS_THRESHOLD (30) is flagged, >= 60 is high risk.
    """

    MAX_INPUT_CHARS = 5000
    SUSPICIOUS_THRESHOLD = 30
    HIGH_RISK_THRESHOLD = 60

    # --- URL PATTERNS ---
    URL_REGEX = re.compile(r'(?:https?://|www\.)[^\s<>"\']+', re.I)
    DOMAIN_TOKEN_REGEX = re.compile(r'(?<![@\w.\-])((?:[a-z0-9\-]+\.)+[a-z0-9\-]{2,})(?:/[^\s<>"\']*)?')
    SUSPICIOUS_TLDS = ['.xyz', '.tk', '.top', '.gq', '.ml', '.click', '.buzz',
                       '.cf', '.ga', '.icu', '.vip', '.cyou', '.rest', '.monster', '.cfd', '.sbs']
    SUSPICIOUS_SHORTENERS = ['bit.ly', 'tinyurl.com', 'cutt.ly', 't.ly', 'rb.gy',
                             'is.gd', 'shorturl.at', 'goo.gl', 'ow.ly', 'tiny.cc', 's.id', 'rebrand.ly']
    # brand token -> official domains. A host containing the brand but not
    # ending in one of these is treated as a spoof.
    BRAND_OFFICIAL_DOMAINS = {
        'sbi': ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com', 'sbi.bank.in', 'sbicard.com', 'sbilife.co.in'],
        'hdfc': ['hdfcbank.com', 'hdfc.com', 'hdfcbank.net', 'hdfclife.com', 'hdfcsec.com'],
        'icici': ['icicibank.com', 'icici.com', 'icicidirect.com', 'iciciprulife.com'],
        'axis': ['axisbank.com', 'axis.bank.in'],
        'pnb': ['pnbindia.in', 'netpnb.com'],
        'kotak': ['kotak.com', 'kotakbank.com'],
        'paytm': ['paytm.com', 'paytmbank.com'],
        'phonepe': ['phonepe.com'],
        'gpay': ['pay.google.com'],
        'amazon': ['amazon.in', 'amazon.com', 'amzn.in', 'amzn.to'],
        'flipkart': ['flipkart.com', 'fkrt.it'],
        'irctc': ['irctc.co.in'],
        'incometax': ['incometax.gov.in', 'incometaxindia.gov.in'],
        'uidai': ['uidai.gov.in'],
        'epfo': ['epfindia.gov.in'],
        'bescom': ['bescom.karnataka.gov.in', 'bescom.co.in'],
        'indiapost': ['indiapost.gov.in'],
    }
    GOV_SUFFIXES = ('.gov.in', '.nic.in')

    # --- BANK / FINANCIAL CONTEXT (All Languages) ---
    BANK_CONTEXT_WORDS = [
        # English
        'sbi', 'hdfc', 'icici', 'axis', 'pnb', 'bob', 'kotak', 'yes bank',
        'bank', 'banking', 'account', 'customer care', 'kyc', 'atm', 'debit', 'debited',
        'credit card', 'upi', 'neft', 'imps', 'rtgs', 'ifsc',
        # Hindi
        'बैंक', 'खाता', 'ग्राहक', 'लेनदेन', 'डेबिट', 'क्रेडिट',
        'केवाईसी', 'एटीएम', 'बैलेंस',
        # Hinglish
        'khata', 'balance', 'credit',
        # Kannada
        'ಬ್ಯಾಂಕ್', 'ಖಾತೆ', 'ಖಾತಾ', 'ವಹಿವಾಟು', 'ಡೆಬಿಟ್', 'ಕ್ರೆಡಿಟ್',
        'ಬ್ಯಾಲೆನ್ಸ್', 'ಕೆವೈಸಿ',
    ]

    # --- CALL/ACTION WORDS (All Languages) ---
    CALL_ACTION_WORDS = [
        # English
        'call', 'contact', 'whatsapp', 'dial', 'ring', 'phone',
        # Hindi
        'कॉल', 'संपर्क', 'फोन',
        # Hinglish
        'call karo', 'contact karo', 'phone karo',
        # Kannada
        'ಕರೆ', 'ಸಂಪರ್ಕ', 'ಫೋನ್',
    ]

    # --- URGENCY WORDS (All Languages) ---
    URGENCY_WORDS = [
        # English
        'urgent', 'urgently', 'immediately', 'act now', 'expire', 'expired', 'expires',
        'blocked', 'suspended', 'closed', 'deactivated', 'limited time',
        'last warning', 'final notice', 'within 24 hours', 'today only', 'right now',
        # Hindi
        'तुरंत', 'जल्दी', 'अभी', 'समय सीमा', 'अंतिम चेतावनी',
        'बंद', 'निलंबित', 'समाप्त',
        # Hinglish
        'turant', 'jaldi', 'abhi', 'block ho jayega',
        'last chance', 'hurry up',
        # Kannada
        'ತಕ್ಷಣ', 'ಈಗ', 'ಅವಧಿ', 'ಕೊನೆಯ ಎಚ್ಚರಿಕೆ',
        'ಬ್ಲಾಕ್', 'ನಿಲ್ಲಿಸಲಾಗಿದೆ', 'ಮುಕ್ತಾಯ',
    ]

    # --- STRONG CATEGORY KEYWORDS (All Languages) ---
    CATEGORY_KEYWORDS = {
        # OTP theft is mostly handled by is_otp_request(); these are extra fixed phrases
        'otp_theft': [
            r're:\botp\s+(?:please|plz|pls)\b',
            r"re:\bwhat(?:'s| is|s)\s+(?:your|the)\s+otp\b",
            r're:\bneed\s+(?:your|the)\s+otp\b',
            'ओटीपी बताओ', 'ओटीपी बताइए', 'अपना ओटीपी बताओ', 'अपना ओटीपी भेजो', 'ओटीपी भेजो',
            'ओटीपी हमें बताएं', 'ओटीपी पढ़कर बताइए',
            'otp batao', 'apna otp batao', 'otp bhejo', 'otp boliye',
            'ಒಟಿಪಿ ಹೇಳಿ', 'ನಿಮ್ಮ ಒಟಿಪಿ ಹೇಳಿ', 'ನಿಮ್ಮ ಒಟಿಪಿ ಕಳುಹಿಸಿ', 'ಒಟಿಪಿ ಕಳುಹಿಸಿ',
            'ಒಟಿಪಿ ನೀಡಿ', 'ನಿಮ್ಮ ಒಟಿಪಿ ನೀಡಿ', 'ಒಟಿಪಿಯನ್ನು ಹಂಚಿಕೊಳ್ಳಿ', 'ನಿಮ್ಮ ಒಟಿಪಿಯನ್ನು ಹಂಚಿಕೊಳ್ಳಿ',
        ],
        'phishing': [
            # English
            'verify your account', 'click here', 'click the link',
            'update kyc', 'update details', 'confirm your identity',
            'verify email', 'verify phone', 'secure your account',
            # Hindi
            'खाता सत्यापित', 'यहां क्लिक', 'लिंक पर क्लिक',
            'केवाईसी अपडेट', 'विवरण अपडेट',
            # Hinglish
            'account verify karo', 'click karo', 'link pe click',
            'kyc update karo', 'details update karo',
            # Kannada
            'ಖಾತೆ ಪರಿಶೀಲಿಸಿ', 'ಕ್ಲಿಕ್ ಮಾಡಿ', 'ಲಿಂಕ್ ಮೇಲೆ ಕ್ಲಿಕ್',
            'ಕೆವೈಸಿ ಅಪ್‌ಡೇಟ್', 'ವಿವರಗಳನ್ನು ಅಪ್‌ಡೇಟ್ ಮಾಡಿ',
        ],
        'lottery': [
            # English
            'lottery', 'prize', 'claim now', 'jackpot',
            'you won', 'you have won', 'congratulations you won', 'lucky draw', 'gift amount',
            # Hindi
            'जीते', 'लॉटरी', 'पुरस्कार', 'क्लेम करें', 'जैकपॉट',
            'बधाई हो आप जीते',
            # Hinglish
            'jeete', 'prize claim karo', 'congratulations aap jeete',
            # Kannada
            'ಗೆದ್ದಿದ್ದೀರಿ', 'ಲಾಟರಿ', 'ಬಹುಮಾನ', 'ಕ್ಲೇಮ್ ಮಾಡಿ',
            'ಅಭಿನಂದನೆಗಳು',
        ],
        'impersonation': [
            # English
            'tax department', 'court notice', 'cbi', 'enforcement directorate',
            'ed notice', 'rbi governor', 'reserve bank',
            # Hindi
            'इनकम टैक्स', 'कोर्ट नोटिस', 'कस्टम्स', 'सीबीआई', 'आरबीआई',
            # Hinglish
            'income tax department', 'police station',
            # Kannada
            'ಆದಾಯ ತೆರಿಗೆ', 'ಪೊಲೀಸ್', 'ಕೋರ್ಟ್ ನೋಟಿಸ್', 'ಕಸ್ಟಮ್ಸ್',
        ],
        'job_scam': [
            # English
            'work from home', 'earn per day', 'job offer', 'part time job',
            'no experience needed', 'earn 50000', 'daily income',
            # Hindi
            'घर बैठे कमाओ', 'रोज़ कमाओ', 'नौकरी ऑफर', 'पार्ट टाइम',
            # Hinglish
            'ghar baithe kamao', 'roz kamao', 'job offer hai',
            'daily earning',
            # Kannada
            'ಮನೆಯಲ್ಲಿ ಕೆಲಸ', 'ದಿನಕ್ಕೆ ಸಂಪಾದಿಸಿ', 'ಉದ್ಯೋಗ ಆಫರ್',
            'ಪಾರ್ಟ್ ಟೈಮ್ ಕೆಲಸ',
        ],
        'investment_scam': [
            # English
            'guaranteed return', 'guaranteed returns', 'double your money', 'crypto profit',
            '300% return', 'risk free investment', 'sure shot profit',
            'trading secret', 'stock tip',
            # Hindi
            'गारंटीड रिटर्न', 'पैसा दोगुना', 'क्रिप्टो प्रॉफिट',
            'जोखिम मुक्त निवेश',
            # Hinglish
            'paisa double', 'sure shot',
            # Kannada
            'ಖಚಿತ ಲಾಭ', 'ಹಣ ದುಪ್ಪಟ್ಟು', 'ಕ್ರಿಪ್ಟೋ ಲಾಭ',
            'ಅಪಾಯರಹಿತ ಹೂಡಿಕೆ',
        ],
        'bank_fraud': [
            # English
            'account blocked', 'account suspended', 'account closed',
            'kyc update required', 'kyc expired', 'card blocked',
            # Hindi
            'खाता ब्लॉक', 'खाता निलंबित', 'केवाईसी अपडेट ज़रूरी',
            'कार्ड ब्लॉक',
            # Hinglish
            'account block ho gaya', 'card block',
            # Kannada
            'ಖಾತೆ ಬ್ಲಾಕ್', 'ಖಾತೆ ನಿಲ್ಲಿಸಲಾಗಿದೆ', 'ಕೆವೈಸಿ ಅಪ್‌ಡೇಟ್ ಬೇಕು',
            'ಕಾರ್ಡ್ ಬ್ಲಾಕ್',
        ],
        'romance_scam': [
            # English
            'send me money', 'need help with bills', 'buy gift card', 'transfer to my account',
            # Hindi
            'पैसे भेजो', 'गिफ्ट कार्ड खरीदो',
            # Hinglish
            'paisa bhejo', 'gift card kharido',
            # Kannada
            'ಹಣ ಕಳುಹಿಸಿ', 'ಗಿಫ್ಟ್ ಕಾರ್ಡ್ ಖರೀದಿಸಿ',
        ],

        # ---------- NEW scam types (mapped to legacy names for the UI) ----------
        'digital_arrest': [
            'digital arrest', 'arrest warrant', 'money laundering case', 'drugs found in your parcel',
            'drugs in your parcel', 'illegal items in your parcel', 'your parcel contains',
            'narcotics', 'do not disconnect the call', 'stay on the video call', 'will be arrested',
            'cyber crime branch', 'supreme court order',
            'डिजिटल अरेस्ट', 'गिरफ्तारी वारंट', 'मनी लॉन्ड्रिंग', 'आपके पार्सल में',
            'warrant jaari', 'arrest ho jayega',
            'ಡಿಜಿಟಲ್ ಅರೆಸ್ಟ್', 'ಬಂಧನ ವಾರಂಟ್', 'ಮನಿ ಲಾಂಡರಿಂಗ್',
        ],
        'fake_courier': [
            'package could not be delivered', 'parcel could not be delivered', 'delivery failed',
            'delivery attempt failed', 'address is incomplete', 'incomplete address',
            'reschedule delivery', 'redelivery fee', 'pay delivery fee', 'customs fee',
            'parcel is held', 'package is held',
            'अधूरा पता', 'डिलीवरी असफल',
            'ವಿಳಾಸ ಅಪೂರ್ಣ', 'ವಿತರಣೆ ವಿಫಲ',
        ],
        'electricity_scam': [
            'electricity will be disconnected', 'power will be disconnected',
            'electricity connection will be disconnected', 'electricity bill not updated',
            'bill not updated', 'disconnected tonight', 'power supply will be cut',
            'electricity disconnection',
            'बिजली कनेक्शन कट', 'बिजली कट', 'बिल अपडेट नहीं',
            'ವಿದ್ಯುತ್ ಸಂಪರ್ಕ ಕಡಿತ', 'ವಿದ್ಯುತ್ ಬಿಲ್ ಅಪ್‌ಡೇಟ್',
        ],
        'upi_refund': [
            'sent by mistake', 'sent you by mistake', 'wrongly sent', 'wrongly transferred',
            'refund the amount', 'collect request', 'approve the request to receive',
            'enter your upi pin to receive', 'enter upi pin to receive',
            'scan qr to receive', 'scan to receive money', 'scan the qr code to receive',
            'paisa galti se',
            # "galti se ... bhej diya" with other words in between (Hinglish / Hindi)
            # a money word must appear between them, so "galti se message delete ho gaya, bhej na" is not flagged
            r're:\bgalti\s+se\s+(?:bhej|bheja|bheji|transfer|send)',
            r're:\bgalti\s+se\b.{0,40}(?:\bpaisa\b|\bpaise\b|\brupaye\b|\brupay\b|\bamount\b|\bmoney\b|\bpayment\b|₹|\brs\b|\binr\b).{0,30}\b(?:bhej|bheja|bheji|transfer|send)',
            r're:गलती से\s*(?:भेज|ट्रांसफर)',
            r're:गलती से.{0,40}(?:पैसे|रुपये|रकम|राशि).{0,30}(?:भेज|ट्रांसफर)',
            'यूपीआई पिन',
            'ತಪ್ಪಾಗಿ ಕಳುಹಿಸ', 'ತಪ್ಪಾಗಿ ಹಣ',
        ],
        'remote_access': [
            r're:\b(?:anydesk|any desk|teamviewer|team viewer|quicksupport|quick support|rustdesk|airdroid|alpemix|ammyy|screen\s?share)\b',
        ],
        'kyc_identity': [
            'aadhaar will be blocked', 'aadhar will be blocked', 'aadhaar blocked',
            'pan card will be blocked', 'pan will be blocked', 'pan card blocked',
            'sim will be blocked', 'sim will be deactivated', 'sim card will be blocked',
            'sim kyc', 'update your aadhaar', 'update your pan', 'pan update',
            'आधार ब्लॉक', 'पैन ब्लॉक', 'सिम ब्लॉक',
            'ಆಧಾರ್ ಬ್ಲಾಕ್', 'ಪ್ಯಾನ್ ಬ್ಲಾಕ್', 'ಸಿಮ್ ಬ್ಲಾಕ್',
        ],
        'loan_app': [
            'instant loan', 'loan approved', 'pre approved loan', 'pre-approved loan',
            'loan without cibil', 'no cibil', 'without documents', 'processing fee',
            'advance fee', 'personal loan offer',
            'पर्सनल लोन', 'लोन मंजूर',
            'ತ್ವರಿತ ಸಾಲ', 'ಸಾಲ ಮಂಜೂರು',
        ],
        'sextortion': [
            'video will be leaked', 'your video will be leaked', 'intimate video', 'nude video',
            'viral your video', 'make your video viral', 'leak your video',
            'वीडियो वायरल', 'वीडियो लीक',
            'ವಿಡಿಯೋ ವೈರಲ್', 'ವಿಡಿಯೋ ಲೀಕ್',
        ],
        'task_scam': [
            'like youtube videos', 'like videos and earn', 'rate hotels', 'prepaid task',
            'complete tasks and earn', 'commission per task', 'telegram group task',
            'review and earn', 'task and earn',
        ],
    }

    # --- WEAK KEYWORDS: low score, only matter in combination ---
    WEAK_KEYWORDS = {
        'romance_scam': ['love you', 'meet me', 'my dear', 'i am lonely', 'army officer', 'emergency help',
                         'madad chahiye', 'मदद चाहिए', 'ಸಹಾಯ ಬೇಕು'],
        'lottery': ['congratulations', 'lucky', 'winner'],
        'job_scam': ['hiring', 'vacancy', 'earn money', 'salary per day'],
        'investment_scam': ['investment', 'profit', 'returns', 'trading group', 'vip group', 'join our telegram'],
        'phishing': ['verify', 'login', 'password', 'update your', 'confirm your'],
        'bank_fraud': ['kyc', 'blocked', 'suspended', 'account debited', 'unauthorized transaction',
                       'खाता ब्लॉक', 'केवाईसी अपडेट', 'unauthorised transaction'],
        'impersonation': ['police', 'income tax', 'court', 'customs', 'arrest', 'legal action', 'fir', 'railway'],
        'fake_courier': ['india post', 'courier'],
        'electricity_scam': ['bescom', 'electricity bill'],
    }

    CATEGORY_WEIGHTS = {
        'otp_theft': 50, 'phishing': 20, 'lottery': 25, 'impersonation': 25,
        'job_scam': 25, 'investment_scam': 25, 'bank_fraud': 25, 'romance_scam': 20,
        'digital_arrest': 50, 'fake_courier': 25, 'electricity_scam': 35, 'upi_refund': 40,
        'remote_access': 45, 'kyc_identity': 30, 'loan_app': 25, 'sextortion': 40,
        'task_scam': 35,
    }
    WEAK_WEIGHT = 8
    PER_CATEGORY_CAP = 60

    # new category -> category name the existing UI already knows
    LEGACY_CATEGORY_MAP = {
        'digital_arrest': 'impersonation',
        'fake_courier': 'phishing',
        'electricity_scam': 'impersonation',
        'upi_refund': 'bank_fraud',
        'remote_access': 'bank_fraud',
        'kyc_identity': 'bank_fraud',
        'loan_app': 'investment_scam',
        'sextortion': 'romance_scam',
        'task_scam': 'job_scam',
        'malicious_apk': 'phishing',
        'fake_debit_alert': 'bank_fraud',
        'sender_mismatch': 'bank_fraud',
        'callback_number': 'impersonation',
        'url_risk': 'phishing',
        'url_spoof': 'bank_fraud',
        'urgency': 'urgency',
    }
    # internal signals that never appear as triggers
    INTERNAL_SIGNALS = ('_combo', '_channel', '_ml')

    # priority used to break ties when choosing the headline category
    CATEGORY_PRIORITY = ['bank_fraud', 'otp_theft', 'phishing', 'impersonation',
                         'investment_scam', 'romance_scam', 'lottery', 'job_scam']

    ADVICE = {
        'otp_theft': 'Never share your OTP, PIN, CVV or password with anyone. Banks and officials never ask for it.',
        'phishing': "Don't click links or install apps from messages. Open the official app or type the website address yourself.",
        'bank_fraud': 'Banks do not ask you to call mobile numbers or share details over SMS/WhatsApp. Use the number on your card or the official website.',
        'impersonation': 'Police, CBI, courts and tax officers never arrest or demand money over phone or video calls. Hang up and verify independently.',
        'lottery': "You can't win a lottery you never entered. Never pay a fee to claim a prize.",
        'job_scam': 'Genuine employers never ask you to pay money or do paid tasks before you earn.',
        'investment_scam': 'No investment can guarantee returns. Check any advisor on the SEBI website.',
        'romance_scam': 'Never send money, gift cards or videos to someone you have not met in person.',
        'social_engineering': 'Be careful with unknown contacts on chat apps. Scammers build trust first, then ask for money or details.',
    }
    REPORT_ADVICE = 'If you already lost money or shared details, call 1930 or report at cybercrime.gov.in immediately.'

    # --- SAFE WORDS (greetings apply only to very short messages) ---
    GREETING_WORDS = [
        'hiii', 'hii', 'hi', 'hey', 'hello', 'thanks', 'thank you',
        'ok', 'okay', 'sure', 'yes', 'no', 'namaste',
        'नमस्ते', 'धन्यवाद', 'ठीक है',
        'ನಮಸ್ಕಾರ', 'ಧನ್ಯವಾದಗಳು', 'ಸರಿ',
    ]
    LEGIT_PHRASES = [
        # English Legit
        'your order', 'order shipped', 'order delivered', 'transaction successful',
        'thank you for shopping', 'payment received', 'bill paid',
        'booking confirmed', 'appointment confirmed', 'ticket confirmed',
        # Hindi Legit
        'ऑर्डर', 'डिलीवरी', 'भुगतान सफल', 'बिल भुगतान',
        'बुकिंग पक्का', 'टिकट पक्का',
        # Hinglish Legit
        'order deliver ho gaya', 'payment successful', 'bill paid ho gaya',
        'booking confirm', 'ticket confirm',
        # Kannada Legit
        'ಆರ್ಡರ್', 'ಡೆಲಿವರಿ', 'ಯಶಸ್ವಿ', 'ಪಾವತಿ ಯಶಸ್ವಿ',
        'ಬಿಲ್ ಪಾವತಿ', 'ಬುಕಿಂಗ್ ಖಚಿತ', 'ಟಿಕೆಟ್ ಖಚಿತ',
    ]
    SAFE_WORDS = GREETING_WORDS + LEGIT_PHRASES   # kept for compatibility

    # --- CHANNEL RISK WEIGHTS (only applied when other signals exist) ---
    CHANNEL_WEIGHTS = {
        'sms': 0,
        'email': 20,
        'whatsapp': 25,
        'telegram': 30,
        'social': 30,
        'voice': 10,
    }

    # --- OTP / SECRET REQUEST DETECTION ---
    SECRET_WORDS = ['otp', 'ओटीपी', 'ಒಟಿಪಿ', 'one time password', 'verification code',
                    'upi pin', 'atm pin', 'cvv', 'card pin', 'mpin', 'm-pin', 'password', 'security code']
    ASK_WORDS = [
        # English
        'share', 'tell', 'give', 'send', 'read', 'provide', 'forward', 'disclose', 'reveal', 'dictate',
        # Hinglish
        'batao', 'bata do', 'bata dijiye', 'bataiye', 'bhejo', 'bhej do', 'boliye', 'bolo', 'dedo', 'de do',
        # Hindi
        'बताओ', 'बताइए', 'बताएं', 'बताएँ', 'बता दो', 'भेजो', 'भेजिए', 'साझा', 'शेयर', 'पढ़कर', 'पढ़ें',
        # Kannada
        'ಹೇಳಿ', 'ಕಳುಹಿಸಿ', 'ಹಂಚಿಕೊಳ್ಳಿ', 'ಹಂಚಿಕೊಳ್ಳ', 'ನೀಡಿ', 'ತಿಳಿಸಿ', 'ಓದಿ',
    ]
    NEG_BEFORE_REGEX = re.compile(
        r"\b(?:do not|don't|dont|never|must not|should not|cannot|can't|not|avoid|mat|nahi|nahin)\b|\bन\b|नहीं|मत|ಬೇಡ")
    NEG_AFTER_REGEX = re.compile(r"\b(?:mat|nahi|nahin|no one|nobody)\b|\bन\b|नहीं|मत|ಬೇಡ")

    # --- PHONE NUMBERS ---
    MOBILE_REGEX = re.compile(r'(?<!\d)(?:\+?91[\s\-]?|0)?([6-9]\d{4}[\s\-]?\d{5})(?!\d)')
    TOLLFREE_REGEX = re.compile(r'(?<!\d)(?:1800|1860)[\s\-]?\d{3}[\s\-]?\d{3,4}(?!\d)')

    # --- TRANSACTION ALERTS ("Rs 500 debited ...") ---
    TXN_ALERT_REGEX = re.compile(
        r'(?:rs\.?|inr|₹)\s?\d[\d,]*(?:\.\d+)?.{0,60}\b(?:debited|credited|withdrawn|spent|deducted)\b'
        r'|\b(?:debited|credited|withdrawn|deducted)\b.{0,40}(?:rs\.?|inr|₹)\s?\d')

    SENDER_HEADER_REGEX = re.compile(r'^[a-z]{2}-[a-z0-9]{3,8}(?:-[a-z])?$', re.I)

    # ==========================================
    # PRE-COMPILED SCRIPT PATTERNS
    # ==========================================
    KANNADA_PATTERN = re.compile(r'[\u0C80-\u0CFF]')
    DEVANAGARI_PATTERN = re.compile(r'[\u0900-\u097F\uA8E0-\uA8FF\u1CD0-\u1CFF]')
    DEVANAGARI_WORD_PATTERN = re.compile(r'[\u0900-\u097F\uA8E0-\uA8FF\u1CD0-\u1CFF]+')
    ENGLISH_WORD_PATTERN = re.compile(r'\b[a-z]{2,}\b')
    OTHER_SCRIPTS = {
        'telugu': re.compile(r'[\u0C00-\u0C7F]'),
        'tamil': re.compile(r'[\u0B80-\u0BFF]'),
        'bengali': re.compile(r'[\u0980-\u09FF]'),
        'gujarati': re.compile(r'[\u0A80-\u0AFF]'),
        'punjabi': re.compile(r'[\u0A00-\u0A7F]'),
        'malayalam': re.compile(r'[\u0D00-\u0D7F]'),
        'odia': re.compile(r'[\u0B00-\u0B7F]'),
    }

    # Hinglish markers. Ambiguous English words (main, to, do, the, hi, sir,
    # na, de, ho, kar, par, ya, ji ...) were removed in v2.
    HINGLISH_WORD_MARKERS = [
        'aap', 'tum', 'hum', 'mein', 'tumhe', 'humne', 'humein', 'aapka', 'aapki', 'aapke', 'apka',
        'tumhara', 'mera', 'hamara', 'apna', 'apne', 'apni', 'tera',
        'hai', 'hain', 'hoga', 'hogi', 'hoge', 'hua', 'hui', 'tha', 'thi',
        'karo', 'karna', 'kiya', 'kariye', 'karein',
        'kya', 'kaisa', 'kaise', 'kitna', 'kitne', 'kab', 'kahan',
        'nahi', 'mat', 'bilkul',
        'bhi', 'toh', 'aur', 'lekin', 'kyunki', 'agar', 'yadi',
        'ye', 'wo', 'yeh', 'woh', 'iska', 'uska',
        'ka', 'ke', 'ki', 'ko', 'pe', 'se', 'liye', 'wala', 'wali', 'wale',
        'chalo', 'aao', 'jao',
        'abhi', 'turant', 'jaldi', 'kal', 'aaj', 'parso',
        'sahab', 'bhai', 'bhaiya', 'didi', 'behna',
        'dijiye', 'bolo', 'batao', 'bataiye', 'dena', 'dedo', 'bhejo', 'bhej',
        'jayega', 'jayegi', 'jayenge', 'aayega', 'aayegi',
        'chahiye', 'zaroor', 'zaruur', 'sahi', 'galat',
        'samjho', 'samjhao', 'sunao', 'suno',
        'hota', 'hoti', 'hote', 'karta', 'karti', 'karte',
        'likha', 'likhi', 'likhe', 'padha', 'padhi', 'padhe',
        'dekho', 'dekhta', 'dekhti', 'dekhte',
        'bolna', 'bolte', 'sunna', 'sunte',
        'paisa', 'paise', 'khata', 'band', 'sirf', 'jeete',
    ]
    HINGLISH_WORD_SET = frozenset(HINGLISH_WORD_MARKERS)

    # Multi-word Hinglish phrases (higher confidence)
    HINGLISH_PHRASES = [
        'kya hai', 'kya hua', 'kaise hai', 'kaisa hai', 'kya kya',
        'karo na', 'batao na', 'bolo na', 'chal na', 'aao na', 'jao na',
        'ho gaya', 'ho jayega', 'ho gayi', 'ho gaye', 'ho sakta',
        'karna hai', 'karna padega', 'karna hoga', 'karna chahiye',
        'mat karo', 'nahi karo', 'nahi hai', 'nahi hoga',
        'ka liye', 'ke liye', 'ke bare', 'ki taraf', 'ki wajah',
        'mein hu', 'mein hoon', 'tum ho', 'hum hain',
        'ye hai', 'wo hai', 'yeh hai', 'woh hai',
        'bata do', 'bta do', 'btao', 'bta dijiye',
        'kya kar', 'kya bata', 'kya bol',
        'se bhi', 'bhi nahi', 'hi nahi', 'toh nahi',
        'par hai', 'pe hai', 'mein hai',
        'ji hai', 'ji hoga', 'ji batao', 'ji sunao',
        'sahi hai', 'sahi bol', 'sahi batao',
        'galat hai', 'galat bol',
        'kya bol raha', 'kya bol rahi', 'kya kar raha', 'kya kar rahi',
        'samajh nahi', 'samjh nahi',
        'aapka account', 'aap ki', 'aap ke', 'tumhara account',
        'block ho jayega', 'block ho gaya', 'block hoga',
        'call karo', 'phone karo', 'contact karo',
        'share karo', 'bhej do', 'send karo',
    ]

    def __init__(self, model_path='model.pkl', vectorizer_path='vectorizer.pkl',
                 expose_new_categories=False):
        self.expose_new_categories = expose_new_categories
        self.model = None
        self.vectorizer = None

        # per-instance copies so keywords.json can extend them safely
        self.CATEGORY_KEYWORDS = {k: list(v) for k, v in ScamShieldAI.CATEGORY_KEYWORDS.items()}
        self.WEAK_KEYWORDS = {k: list(v) for k, v in ScamShieldAI.WEAK_KEYWORDS.items()}
        self.LEGACY_CATEGORY_MAP = dict(ScamShieldAI.LEGACY_CATEGORY_MAP)
        self.CATEGORY_WEIGHTS = dict(ScamShieldAI.CATEGORY_WEIGHTS)
        self._load_extra_keywords()
        self._build_matchers()

        model_path, vectorizer_path = _resolve_path(model_path), _resolve_path(vectorizer_path)
        if os.path.exists(model_path) and os.path.exists(vectorizer_path):
            try:
                self.model = _load_pickle(model_path)
                self.vectorizer = _load_pickle(vectorizer_path)
            except Exception as e:
                log.warning('ScamShield: ML model not loaded (%s)', e)
                self.model = None
                self.vectorizer = None

    # ==========================================
    # SETUP
    # ==========================================
    def _load_extra_keywords(self):
        """
        Optional keywords.json (next to this file, or SCAMSHIELD_KEYWORDS_FILE):
        {
          "categories": {"phishing": ["new phrase"], "my_new_cat": ["x"]},
          "weak": {"phishing": ["maybe"]},
          "weights": {"my_new_cat": 30},
          "legacy_map": {"my_new_cat": "phishing"}
        }
        """
        path = os.environ.get('SCAMSHIELD_KEYWORDS_FILE') or os.path.join(MODULE_DIR, 'keywords.json')
        if not os.path.exists(path):
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for cat, words in data.get('categories', {}).items():
                self.CATEGORY_KEYWORDS.setdefault(cat, []).extend(words)
            for cat, words in data.get('weak', {}).items():
                self.WEAK_KEYWORDS.setdefault(cat, []).extend(words)
            self.CATEGORY_WEIGHTS.update(data.get('weights', {}))
            self.LEGACY_CATEGORY_MAP.update(data.get('legacy_map', {}))
        except Exception as e:
            log.warning('ScamShield: could not read %s (%s)', path, e)

    def _build_matchers(self):
        self._cat_matchers = {c: build_matcher(k) for c, k in self.CATEGORY_KEYWORDS.items()}
        self._weak_matchers = {c: build_matcher(k) for c, k in self.WEAK_KEYWORDS.items()}
        self._bank_matcher = build_matcher(self.BANK_CONTEXT_WORDS)
        self._call_matcher = build_matcher(self.CALL_ACTION_WORDS)
        self._urgency_matcher = build_matcher(self.URGENCY_WORDS)
        self._greeting_matcher = build_matcher(self.GREETING_WORDS)
        self._legit_matcher = build_matcher(self.LEGIT_PHRASES)
        self._secret_matcher = build_matcher(self.SECRET_WORDS)
        self._ask_matcher = build_matcher(self.ASK_WORDS)

    # ==========================================
    # PREPROCESSING
    # ==========================================
    def preprocess_text(self, text):
        """Lowercase and normalize text, keep alphanumeric + Indic scripts (used for ML)."""
        text = normalize_text(text)
        text = re.sub(r'[^a-z0-9\u0900-\u097F\u0C80-\u0CFF\s]', ' ', text)
        return re.sub(r'\s+', ' ', text).strip()

    def detect_language(self, text):
        """
        Returns: 'english', 'hindi', 'hinglish', 'kannada', 'unknown'
        (or 'telugu', 'tamil', 'bengali', 'gujarati', 'punjabi', 'malayalam',
        'odia' when that script dominates).
        """
        if not text or not text.strip():
            return 'unknown'

        text_lower = text.lower().strip()

        has_kannada = bool(self.KANNADA_PATTERN.search(text))
        has_devanagari = bool(self.DEVANAGARI_PATTERN.search(text))
        kannada_count = len(self.KANNADA_PATTERN.findall(text))
        devanagari_count = len(self.DEVANAGARI_PATTERN.findall(text))
        english_words = self.ENGLISH_WORD_PATTERN.findall(text_lower)

        # ---------- Kannada ----------
        if has_kannada:
            if has_devanagari:
                return 'kannada' if kannada_count >= devanagari_count else 'hindi'
            if kannada_count >= 2:
                return 'kannada'
            total_alpha = len(re.findall(r'[a-zA-Z\u0C80-\u0CFF]', text))
            if total_alpha > 0 and kannada_count / total_alpha > 0.3:
                return 'kannada'

        # ---------- Hindi vs Hinglish (Devanagari present) ----------
        if has_devanagari:
            devanagari_word_count = len(self.DEVANAGARI_WORD_PATTERN.findall(text))
            common_bilingual = {
                'is', 'for', 'and', 'the', 'to', 'in', 'of', 'your', 'you',
                'not', 'no', 'with', 'this', 'that', 'from', 'has', 'have',
                'will', 'be', 'or', 'on', 'at', 'by', 'an', 'as', 'it',
                'if', 'do', 'we', 'he', 'she', 'they', 'my', 'me', 'us',
                'http', 'https', 'www', 'com', 'org', 'net', 'xyz', 'top',
                'sms', 'msg', 'otp', 'upi', 'kyc', 'atm', 'sbi', 'hdfc',
                'icici', 'axis', 'pnb', 'bob',
            }
            filtered_english = [w for w in english_words if w not in common_bilingual]
            total_content_words = devanagari_word_count + len(filtered_english)
            if total_content_words == 0:
                return 'hindi'
            return 'hindi' if devanagari_word_count / total_content_words >= 0.6 else 'hinglish'

        # ---------- Other Indian scripts ----------
        if not has_kannada:
            for name, pat in self.OTHER_SCRIPTS.items():
                if len(pat.findall(text)) >= 2:
                    return name

        # ---------- Hinglish vs English (Latin only) ----------
        if not has_kannada:
            tokens = re.findall(r"[a-z']+", text_lower)
            hinglish_word_count = sum(1 for w in tokens if w in self.HINGLISH_WORD_SET)
            padded = ' ' + ' '.join(tokens) + ' '
            phrase_count = sum(1 for p in self.HINGLISH_PHRASES if (' ' + p + ' ') in padded)
            score = hinglish_word_count + phrase_count * 3

            word_count = len(text_lower.split())
            if word_count == 0:
                return 'english'
            density = score / word_count

            if word_count <= 2:
                threshold = 0.8
            elif word_count <= 4:
                threshold = 0.5
            elif word_count <= 8:
                threshold = 0.3
            else:
                threshold = 0.15

            return 'hinglish' if (score >= 2 and density >= threshold) else 'english'

        return 'english'

    # ==========================================
    # SIGNAL GENERATORS  (each returns a list of (category, score, reason))
    # ==========================================
    def _extract_urls(self, t):
        found = []
        for u in self.URL_REGEX.findall(t):
            found.append(u.rstrip('.,;:!?)]}\'"'))
        joined = ' '.join(found)
        for m in self.DOMAIN_TOKEN_REGEX.finditer(t):
            domain = m.group(1)
            if domain in joined:
                continue
            tld = '.' + domain.rsplit('.', 1)[-1]
            if tld in self.SUSPICIOUS_TLDS or self._is_shortener(domain):
                found.append(m.group(0).rstrip('.,;:!?)]}\'"'))
        seen, out = set(), []
        for u in found:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out[:10]

    def _is_shortener(self, host):
        return any(host == s or host.endswith('.' + s) for s in self.SUSPICIOUS_SHORTENERS)

    def _url_signals(self, urls):
        signals = []
        for url in urls:
            full = url if re.match(r'https?://', url) else 'http://' + url
            try:
                p = urlparse(full)
                host = (p.hostname or '').lower()
            except ValueError:
                continue
            if not host:
                continue
            gov = host.endswith(self.GOV_SUFFIXES)

            if not gov and any(host.endswith(tld) for tld in self.SUSPICIOUS_TLDS):
                signals.append(('url_risk', 30, 'Link uses a high-risk domain (%s)' % host))
            if self._is_shortener(host):
                signals.append(('url_risk', 25, 'Link is hidden behind a URL shortener (%s)' % host))
            if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', host):
                signals.append(('url_risk', 30, 'Link points to a raw IP address'))
            if 'xn--' in host:
                signals.append(('url_risk', 30, 'Link uses a look-alike (punycode) domain'))
            if '@' in p.netloc:
                signals.append(('url_risk', 20, 'Link hides its real destination using "@"'))
            if p.path.lower().endswith('.apk') or '.apk' in url:
                signals.append(('malicious_apk', 40, 'Link downloads an APK app file'))
            if not gov:
                for brand, official in self.BRAND_OFFICIAL_DOMAINS.items():
                    if re.search(r'(?:^|[.\-])' + re.escape(brand), host):
                        if not any(host == d or host.endswith('.' + d) for d in official):
                            signals.append(('url_spoof', 35,
                                            'Domain imitates "%s" but is not an official %s site (%s)' % (brand, brand, host)))
                            break
        # de-duplicate
        out, seen = [], set()
        for s in signals:
            if (s[0], s[2]) not in seen:
                seen.add((s[0], s[2]))
                out.append(s)
        return out

    def is_otp_request(self, t):
        """True if the message ASKS the reader to share an OTP/PIN/password (negation aware)."""
        if self._secret_matcher is None or self._ask_matcher is None:
            return False
        for sm in self._secret_matcher.finditer(t):
            ws, we = max(0, sm.start() - 40), min(len(t), sm.end() + 40)
            for am in self._ask_matcher.finditer(t, ws, we):
                before = t[max(0, am.start() - 28):am.start()]
                after = t[am.end():am.end() + 14]
                if self.NEG_BEFORE_REGEX.search(before) or self.NEG_AFTER_REGEX.search(after):
                    continue
                return True
        return False

    def _keyword_signals(self, t):
        signals = []
        for cat, matcher in self._cat_matchers.items():
            hit = _search(matcher, t)
            if hit:
                w = self.CATEGORY_WEIGHTS.get(cat, 25)
                signals.append((cat, w, 'Matched %s pattern: "%s"' % (cat.replace('_', ' '), hit.strip())))
        for cat, matcher in self._weak_matchers.items():
            hit = _search(matcher, t)
            if hit:
                signals.append((cat, self.WEAK_WEIGHT, 'Weak %s hint: "%s"' % (cat.replace('_', ' '), hit.strip())))
        return signals

    def _phone_signals(self, t, bank_ctx, call_action, txn_alert):
        signals = []
        mobiles = self.MOBILE_REGEX.findall(t)
        if not mobiles:
            return signals, False
        if call_action:
            signals.append(('callback_number', 20, 'Asks you to call/contact a mobile number'))
            if bank_ctx:
                signals.append(('bank_fraud', 25,
                                'Bank/financial message asking you to call a mobile number (banks use toll-free numbers)'))
        elif bank_ctx and not txn_alert:
            signals.append(('bank_fraud', 10, 'Bank/financial message that includes a mobile number'))
        return signals, bool(call_action)

    # ==========================================
    # PUBLIC HELPERS KEPT FROM v1  (return (score, triggers))
    # ==========================================
    def _legacy_name(self, cat):
        if cat in self.INTERNAL_SIGNALS:
            return None
        return self.LEGACY_CATEGORY_MAP.get(cat, cat)

    def _to_score_triggers(self, signals):
        score = sum(s[1] for s in signals)
        triggers = []
        for s in signals:
            name = self._legacy_name(s[0])
            if name and name not in triggers:
                triggers.append(name)
        return score, triggers

    def check_url_safety(self, text):
        return self._to_score_triggers(self._url_signals(self._extract_urls(normalize_text(text))))

    def analyze_phone_numbers(self, text, text_lower):
        t = normalize_text(text_lower)
        if is_legit_otp_pattern(t):
            return 0, []
        bank = bool(_search(self._bank_matcher, t))
        call = bool(_search(self._call_matcher, t))
        sigs, _ = self._phone_signals(t, bank, call, bool(self.TXN_ALERT_REGEX.search(t)))
        return self._to_score_triggers(sigs)

    def categorize_keywords(self, text_lower):
        return self._to_score_triggers([s for s in self._keyword_signals(normalize_text(text_lower)) if s[1] > self.WEAK_WEIGHT])

    def check_urgency(self, text_lower):
        if _search(self._urgency_matcher, normalize_text(text_lower)):
            return 10, ['urgency']
        return 0, []

    def apply_safe_word_reduction(self, text_lower, current_score):
        """Greetings only count for very short messages; legit phrases reduce by 15."""
        t = normalize_text(text_lower)
        reduction = 0
        if _search(self._greeting_matcher, t) and len(t.split()) <= 4:
            reduction = 25
        elif _search(self._legit_matcher, t):
            reduction = 15
        return max(0, current_score - reduction)

    def ml_classify(self, text):
        """Optional ML classifier (English only). Returns (score, triggers)."""
        p = self._ml_probability(text)
        if p is None or p <= 0.5:
            return 0, []
        score = int((p - 0.5) * 2 * 40)          # 0..40
        return score, (['phishing'] if p >= 0.85 else [])

    def _ml_probability(self, text):
        if not self.model or not self.vectorizer:
            return None
        try:
            vec = self.vectorizer.transform([text])
            proba = self.model.predict_proba(vec)[0]
            return float(proba[1]) if len(proba) > 1 else 0.0
        except Exception:
            return None

    # ==========================================
    # MAIN ANALYSIS PIPELINE
    # ==========================================
    def _empty_result(self, channel):
        return {
            'score': 0, 'category': 'safe', 'triggers': [], 'language': 'unknown',
            'channel': channel, 'risk_level': 'low', 'confidence': 0.5,
            'reasons': [], 'advice': [], 'sub_categories': [],
        }

    def analyze_text(self, text, channel='sms', sender=None):
        """
        Main entry point.
        Returns a dict with:
          score (0-100), category, triggers, language, channel   <- same as v1
          risk_level, confidence, reasons, advice, sub_categories <- new
        `sender` is optional (phone number or SMS header like 'VK-HDFCBK').
        """
        channel = (channel or 'sms').lower()
        if not isinstance(text, str) or not text.strip():
            return self._empty_result(channel)

        text = text[:self.MAX_INPUT_CHARS]
        t = normalize_text(text)
        language = self.detect_language(t)
        signals = []

        # ---- 1. URLs ----
        urls = self._extract_urls(t)
        url_signals = self._url_signals(urls)
        signals += url_signals
        url_risky = bool(url_signals)

        # ---- 2. OTP / secret request ----
        otp_req = self.is_otp_request(t)
        if otp_req:
            signals.append(('otp_theft', self.CATEGORY_WEIGHTS['otp_theft'],
                            'Asks you to share an OTP, PIN or password'))

        # ---- 3. Keywords ----
        kw_signals = self._keyword_signals(t)
        # fixed-phrase OTP hits count only once with the detector
        if otp_req:
            kw_signals = [s for s in kw_signals if not (s[0] == 'otp_theft')]
        signals += kw_signals
        strong_kw = [s for s in kw_signals if s[1] > self.WEAK_WEIGHT]

        # ---- genuine OTP early exit ----
        if (not otp_req and not url_risky and not strong_kw
                and is_legit_otp_pattern(t) and re.search(r'\d{4,8}', t)):
            res = self._build_result(0, [], language, channel, [])
            res['reasons'] = ['Looks like a genuine OTP message: no request to share it, no link and no call-back number.']
            return res

        # ---- 4. Phone numbers ----
        bank_ctx = bool(_search(self._bank_matcher, t))
        call_action = bool(_search(self._call_matcher, t))
        txn_alert = bool(self.TXN_ALERT_REGEX.search(t))
        phone_signals, mobile_call = self._phone_signals(t, bank_ctx, call_action, txn_alert)
        signals += phone_signals

        # ---- 5. Remote access / APK flags used for combos ----
        remote = any(s[0] == 'remote_access' for s in signals)
        apk = any(s[0] == 'malicious_apk' for s in signals)

        # fake bank alert: looks like a debit alert but pushes a link / mobile call-back
        action_threat = url_risky or mobile_call or otp_req or remote
        if txn_alert and action_threat:
            signals.append(('fake_debit_alert', 30,
                            'Looks like a debit alert but asks you to click or call (real alerts do not)'))

        # ---- 6. Urgency ----
        urgency_hit = _search(self._urgency_matcher, t)
        if urgency_hit:
            signals.append(('urgency', 10, 'Pressure / urgency wording: "%s"' % urgency_hit.strip()))

        # ---- 7. Sender ----
        if sender:
            s = re.sub(r'[\s\-]', '', str(sender))
            is_mobile = bool(re.fullmatch(r'(?:\+?91|0)?[6-9]\d{9}', s))
            if is_mobile and (bank_ctx or any(x[0] in ('bank_fraud', 'impersonation', 'digital_arrest') for x in signals)):
                signals.append(('sender_mismatch', 20,
                                'Bank/authority style message sent from a normal mobile number, not a registered sender ID'))

        # ---- 8. ML (English only) ----
        if language == 'english':
            p = self._ml_probability(self.preprocess_text(text))
            if p is not None and p > 0.5:
                signals.append(('_ml', int((p - 0.5) * 2 * 40), 'ML model rated the text as likely spam (%.0f%%)' % (p * 100)))
                if p >= 0.85:
                    signals.append(('phishing', 0, 'ML model flagged phishing-like content'))

        # ---- 9. Combination bonuses ----
        categories_present = {s[0] for s in signals if s[1] > 0}
        authority = bank_ctx or bool(categories_present & {'bank_fraud', 'impersonation', 'digital_arrest',
                                                           'kyc_identity', 'electricity_scam', 'url_spoof'})
        action = bool(urls) or mobile_call or otp_req or remote or apk
        if authority and urgency_hit and action:
            signals.append(('_combo', 15, 'Combination: official-looking claim + urgency + something to click, call or share'))
        elif urgency_hit and url_risky:
            signals.append(('_combo', 10, 'Combination: urgency + suspicious link'))

        # ---- 10. Aggregate (cap per category) ----
        per_cat = {}
        for cat, score, _ in signals:
            if cat in ('_combo', '_channel', '_ml'):
                continue
            per_cat[cat] = min(self.PER_CATEGORY_CAP, per_cat.get(cat, 0) + score)
        total = sum(per_cat.values())
        total += sum(s[1] for s in signals if s[0] in ('_combo', '_ml'))

        # ---- 11. Channel weight: only when something else already looks wrong ----
        channel_weight = self.CHANNEL_WEIGHTS.get(channel, 0)
        if total > 0 and channel_weight:
            total += channel_weight
            signals.append(('_channel', channel_weight, 'Higher-risk channel (%s)' % channel))

        # ---- 12. Safe-word reduction (never for strong evidence) ----
        strong = (otp_req or remote or url_risky or any(v >= 40 for v in per_cat.values()))
        if not strong and len([c for c, v in per_cat.items() if v > 0 and c != 'urgency']) <= 1:
            total = self.apply_safe_word_reduction(t, total)

        total = max(0, min(100, total))

        res = self._build_result(total, signals, language, channel, per_cat)
        if language in self.OTHER_SCRIPTS and res['category'] == 'safe':
            res['reasons'].append('Language not fully supported yet: only links, numbers and English terms were checked.')
        return res

    # ==========================================
    # RESULT BUILDER
    # ==========================================
    def _build_result(self, total, signals, language, channel, per_cat):
        flagged = total >= self.SUSPICIOUS_THRESHOLD
        triggers, sub_categories, reasons = [], [], []

        if flagged:
            # headline category = the one with the highest score; ties use CATEGORY_PRIORITY
            scored = {}
            for cat, score, _ in signals:
                if cat in self.INTERNAL_SIGNALS or score <= 0 or cat == 'urgency':
                    continue
                scored[cat] = scored.get(cat, 0) + score

            def rank(item):
                cat, score = item
                legacy = self._legacy_name(cat)
                pri = self.CATEGORY_PRIORITY.index(legacy) if legacy in self.CATEGORY_PRIORITY else 99
                return (-min(score, self.PER_CATEGORY_CAP), pri)

            ordered = sorted(scored.items(), key=rank)
            for cat, _ in ordered:
                sub_categories.append(cat)
                legacy = self._legacy_name(cat)
                if legacy and legacy not in triggers:
                    triggers.append(legacy)
            if any(s[0] == 'urgency' and s[1] > 0 for s in signals):
                triggers.append('urgency')
            if channel in ('whatsapp', 'telegram', 'social'):
                triggers.append('social_engineering')

            if ordered:
                top = ordered[0][0]
                category = top if self.expose_new_categories else self._legacy_name(top)
            else:
                category = 'suspicious'
            if category in (None, 'urgency'):
                category = 'suspicious'
            reasons = [s[2] for s in sorted(signals, key=lambda x: -x[1]) if s[1] > 0][:8]
        else:
            category = 'safe'
            # weak signals are kept as info only
            reasons = [s[2] for s in sorted(signals, key=lambda x: -x[1]) if s[1] > 0][:3]
            if reasons:
                reasons = ['Minor signals only (below the alert threshold): ' + '; '.join(reasons)]

        risk_level = 'high' if total >= self.HIGH_RISK_THRESHOLD else ('medium' if flagged else 'low')

        if flagged:
            n_cats = len({c for c in sub_categories})
            confidence = round(min(0.98, 0.5 + total / 200.0 + 0.05 * max(0, n_cats - 1)), 2)
        else:
            confidence = round(max(0.5, min(0.95, 0.95 - total / 100.0)), 2)

        advice = []
        if flagged:
            for trig in triggers:
                a = self.ADVICE.get(trig)
                if a and a not in advice:
                    advice.append(a)
            advice.append(self.REPORT_ADVICE)

        return {
            'score': int(total),
            'category': category,
            'triggers': triggers,
            'language': language,
            'channel': channel,
            'risk_level': risk_level,
            'confidence': confidence,
            'reasons': reasons,
            'advice': advice,
            'sub_categories': sub_categories,
        }

    # ==========================================
    # VOICE CALL ANALYSIS
    # ==========================================
    _whisper_model = None
    _whisper_failed = False

    def _transcribe_whisper(self, audio_path):
        """Optional: pip install faster-whisper. Handles Hindi/Kannada/code-switching far better."""
        if ScamShieldAI._whisper_failed:
            raise ImportError('whisper unavailable')
        if ScamShieldAI._whisper_model is None:
            try:
                from faster_whisper import WhisperModel
                ScamShieldAI._whisper_model = WhisperModel(
                    os.environ.get('SCAMSHIELD_WHISPER_MODEL', 'small'),
                    device='cpu', compute_type='int8')
            except ImportError:
                ScamShieldAI._whisper_failed = True
                raise
        segments, info = ScamShieldAI._whisper_model.transcribe(audio_path, beam_size=5, vad_filter=True)
        text = ' '.join(s.text.strip() for s in segments).strip()
        return text, getattr(info, 'language', None)

    def _analyze_voice_google(self, audio_path):
        try:
            from speech_recognition import AudioFile, Recognizer
        except ImportError:
            return {'error': 'speech_recognition not installed. Run: pip install SpeechRecognition'}

        tmp_path = None
        try:
            file_to_read = audio_path
            try:
                from pydub import AudioSegment
                fd, tmp_path = tempfile.mkstemp(suffix='.wav')   # unique per request
                os.close(fd)
                AudioSegment.from_file(audio_path).export(tmp_path, format='wav')
                file_to_read = tmp_path
            except ImportError:
                pass
            except Exception as e:
                return {'error': 'Audio format conversion failed: %s. Install FFmpeg.' % e}

            recognizer = Recognizer()
            with AudioFile(file_to_read) as source:
                audio_data = recognizer.record(source)   # no ambient-noise step: it clips the first 0.5s

            best = None
            for lang in ('en-IN', 'hi-IN', 'kn-IN'):
                try:
                    transcript = recognizer.recognize_google(audio_data, language=lang)
                except Exception:
                    continue
                if not transcript:
                    continue
                res = self.analyze_text(transcript, channel='voice')
                res['transcript'] = transcript
                res['transcript_language'] = lang
                if best is None or res['score'] > best['score']:
                    best = res          # keep the most alarming reading, not just the first one
            if best is None:
                return {'error': 'Could not transcribe audio. No speech detected.'}
            return best
        except Exception as e:
            return {'error': str(e)}
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def analyze_voice_call(self, audio_path):
        """Transcribe audio and analyze the transcript."""
        if not audio_path or not os.path.exists(audio_path):
            return {'error': 'Audio file not found.'}

        if os.environ.get('SCAMSHIELD_USE_WHISPER', '1') == '1':
            try:
                transcript, lang = self._transcribe_whisper(audio_path)
                if not transcript:
                    return {'error': 'Could not transcribe audio. No speech detected.'}
                result = self.analyze_text(transcript, channel='voice')
                result['transcript'] = transcript
                if lang:
                    result['transcript_language'] = lang
                return result
            except ImportError:
                pass                      # faster-whisper not installed -> Google fallback
            except Exception as e:
                log.warning('ScamShield: whisper failed (%s), falling back to Google', e)

        return self._analyze_voice_google(audio_path)


# ==========================================
# SINGLETON INSTANCE
# ==========================================
ai = ScamShieldAI()