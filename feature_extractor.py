import re
import math
from urllib.parse import urlparse
from collections import Counter

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm',
    'banking', 'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
    'password', 'credential', 'wallet', 'payment', 'transfer', 'suspended',
    'limited', 'unusual', 'alert', 'security', 'click', 'free', 'winner',
    'prize', 'urgent', 'validate', 'verification', 'billing', 'support',
    'recover', 'restore', 'unlock', 'authorize', 'authenticate'
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work',
    '.link', '.click', '.download', '.review', '.science', '.win', '.bid',
    '.loan', '.racing', '.date', '.faith', '.party', '.stream', '.gdn',
    '.men', '.accountant', '.trade', '.webcam', '.country', '.kim', '.cricket'
]

COMMON_BRANDS = [
    'paypal', 'amazon', 'google', 'facebook', 'microsoft', 'apple',
    'netflix', 'instagram', 'twitter', 'linkedin', 'ebay', 'chase',
    'wellsfargo', 'bankofamerica', 'citibank', 'dropbox', 'spotify'
]

IP_PATTERN = re.compile(r'(\d{1,3}\.){3}\d{1,3}')


def calculate_entropy(text):
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def extract_features(url):
    """Extract 24 numerical features from a URL for phishing detection."""
    try:
        if url.startswith(('http://', 'https://')):
            parsed = urlparse(url)
        else:
            parsed = urlparse('http://' + url)
    except Exception:
        parsed = urlparse('')

    netloc = parsed.netloc or ''
    path = parsed.path or ''
    query = parsed.query or ''

    # Strip port for domain analysis
    domain = netloc.split(':')[0] if ':' in netloc else netloc

    f = {}

    # 1. url_length
    f['url_length'] = len(url)

    # 2. domain_length
    f['domain_length'] = len(domain)

    # 3. has_ip — IP address used as domain
    f['has_ip'] = 1 if IP_PATTERN.fullmatch(domain) else 0

    # 4. is_https
    f['is_https'] = 1 if url.startswith('https://') else 0

    # 5. num_dots
    f['num_dots'] = url.count('.')

    # 6. num_hyphens
    f['num_hyphens'] = url.count('-')

    # 7. num_underscores
    f['num_underscores'] = url.count('_')

    # 8. num_slashes
    f['num_slashes'] = url.count('/')

    # 9. num_at — @ in URL tricks browser into treating left part as credentials
    f['num_at'] = 1 if '@' in url else 0

    # 10. num_ampersand
    f['num_ampersand'] = url.count('&')

    # 11. num_question
    f['num_question'] = url.count('?')

    # 12. num_equal
    f['num_equal'] = url.count('=')

    # 13. num_digits_in_domain
    f['num_digits_in_domain'] = sum(c.isdigit() for c in domain)

    # 14. suspicious_keywords
    url_lower = url.lower()
    f['suspicious_keywords'] = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # 15. suspicious_tld
    f['suspicious_tld'] = 1 if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0

    # 16. has_subdomain
    parts = domain.split('.')
    f['has_subdomain'] = 1 if len(parts) > 2 else 0

    # 17. subdomain_length
    f['subdomain_length'] = len('.'.join(parts[:-2])) if len(parts) > 2 else 0

    # 18. path_length
    f['path_length'] = len(path)

    # 19. query_length
    f['query_length'] = len(query)

    # 20. url_entropy — high entropy suggests obfuscation
    f['url_entropy'] = round(calculate_entropy(url), 4)

    # 21. brand_in_path — brand name appears in path but not as the domain
    domain_lower = domain.lower()
    f['brand_in_path'] = 1 if any(
        b in path.lower() and b not in domain_lower for b in COMMON_BRANDS
    ) else 0

    # 22. has_port — non-standard port is suspicious
    f['has_port'] = 1 if ':' in netloc and netloc.split(':')[-1].isdigit() else 0

    # 23. special_char_ratio
    safe_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/:.-_?=&#+%')
    special = sum(1 for c in url if c not in safe_chars)
    f['special_char_ratio'] = round(special / max(len(url), 1), 4)

    # 24. double_slash — redirect trick (e.g. http://evil.com//legit.com)
    after_scheme = url[url.find('://') + 3:] if '://' in url else url
    f['double_slash'] = 1 if '//' in after_scheme else 0

    return f


def get_feature_names():
    return [
        'url_length', 'domain_length', 'has_ip', 'is_https', 'num_dots',
        'num_hyphens', 'num_underscores', 'num_slashes', 'num_at',
        'num_ampersand', 'num_question', 'num_equal', 'num_digits_in_domain',
        'suspicious_keywords', 'suspicious_tld', 'has_subdomain',
        'subdomain_length', 'path_length', 'query_length', 'url_entropy',
        'brand_in_path', 'has_port', 'special_char_ratio', 'double_slash'
    ]
