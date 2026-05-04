"""
Synthetic phishing URL dataset generator.
Produces ~6000 labelled URLs: 3000 legitimate (0) + 3000 phishing (1).
"""

import random
import sys
import os
import pandas as pd
from tqdm import tqdm

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from feature_extractor import extract_features, get_feature_names

random.seed(42)

# ---------------------------------------------------------------------------
# Legitimate URL components
# ---------------------------------------------------------------------------
LEGIT_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
    'twitter.com', 'instagram.com', 'linkedin.com', 'reddit.com', 'github.com',
    'stackoverflow.com', 'microsoft.com', 'apple.com', 'netflix.com', 'spotify.com',
    'dropbox.com', 'slack.com', 'zoom.us', 'salesforce.com', 'adobe.com',
    'cloudflare.com', 'stripe.com', 'twilio.com', 'heroku.com', 'digitalocean.com',
    'npmjs.com', 'pypi.org', 'docker.com', 'kubernetes.io', 'reactjs.org',
    'vuejs.org', 'angular.io', 'nodejs.org', 'python.org', 'rust-lang.org',
    'golang.org', 'tensorflow.org', 'pytorch.org', 'pandas.pydata.org', 'numpy.org',
    'medium.com', 'dev.to', 'techcrunch.com', 'forbes.com', 'bloomberg.com',
    'reuters.com', 'bbc.com', 'cnn.com', 'nytimes.com', 'theguardian.com',
    'coursera.org', 'udemy.com', 'edx.org', 'khanacademy.org', 'pluralsight.com',
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com', 'paypal.com',
    'ebay.com', 'etsy.com', 'shopify.com', 'walmart.com', 'target.com',
    'notion.so', 'figma.com', 'canva.com', 'airtable.com', 'trello.com',
    'atlassian.com', 'jira.com', 'confluence.com', 'bitbucket.org', 'gitlab.com',
    'aws.amazon.com', 'azure.microsoft.com', 'cloud.google.com',
    'docs.python.org', 'developer.mozilla.org', 'w3schools.com',
    'geeksforgeeks.org', 'leetcode.com', 'hackerrank.com', 'codepen.io',
    'replit.com', 'codesandbox.io', 'vercel.com', 'netlify.com', 'render.com',
    'twitch.tv', 'discord.com', 'telegram.org', 'whatsapp.com', 'signal.org',
    'protonmail.com', 'gmail.com', 'outlook.com', 'yahoo.com', 'icloud.com',
]

LEGIT_PATHS = [
    '/', '/about', '/contact', '/products', '/services', '/blog', '/news',
    '/login', '/signup', '/dashboard', '/profile', '/settings', '/help',
    '/docs', '/api', '/pricing', '/features', '/download', '/support',
    '/search?q=python+tutorial', '/search?q=machine+learning+basics',
    '/products/laptop?id=12345&color=black', '/category/electronics',
    '/blog/post/getting-started-with-flask', '/news/technology/2024',
    '/docs/getting-started', '/api/v2/reference', '/api/v1/users',
    '/user/johndoe/repos', '/questions/12345/how-to-use-pandas',
    '/watch?v=dQw4w9WgXcQ', '/playlist?list=PLrandomstring',
    '/r/MachineLearning', '/r/Python/comments/abcdef',
    '/package/numpy', '/package/scikit-learn',
    '/courses/machine-learning', '/learn/python',
    '/en/latest/tutorial/', '/en/stable/reference/',
    '/wiki/Machine_learning', '/wiki/Phishing',
    '/home', '/index.html', '/main', '/portal',
    '/account/orders', '/account/wishlist',
    '/shop/item/9876', '/deals/today',
    '/terms', '/privacy', '/cookies',
    '/careers', '/press', '/investors',
    '/open-source', '/community', '/forum',
    '/status', '/changelog', '/roadmap',
]

LEGIT_SUBDOMAINS = [
    'www', 'api', 'docs', 'blog', 'mail', 'app', 'cloud', 'portal',
    'developers', 'help', 'support', 'status', 'cdn', 'assets', 'static',
]


def make_legitimate_url():
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    scheme = 'https://'

    # Occasionally add a legitimate subdomain
    if random.random() < 0.3 and not domain.startswith(('aws.', 'azure.', 'cloud.', 'docs.', 'developer.')):
        sub = random.choice(LEGIT_SUBDOMAINS)
        return f"{scheme}{sub}.{domain}{path}"

    return f"{scheme}{domain}{path}"


# ---------------------------------------------------------------------------
# Phishing URL components
# ---------------------------------------------------------------------------
PHISH_SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work',
    '.link', '.click', '.download', '.win', '.bid', '.loan', '.racing',
    '.date', '.faith', '.party', '.stream', '.men', '.accountant', '.trade',
]

PHISH_BRANDS = [
    'paypal', 'amazon', 'google', 'facebook', 'microsoft', 'apple',
    'netflix', 'instagram', 'twitter', 'linkedin', 'ebay', 'chase',
    'wellsfargo', 'bankofamerica', 'citibank', 'dropbox', 'spotify',
    'youtube', 'gmail', 'outlook', 'yahoo', 'icloud', 'whatsapp',
]

PHISH_ACTIONS = [
    'verify', 'secure', 'login', 'signin', 'account', 'update',
    'confirm', 'validate', 'authenticate', 'recover', 'unlock',
    'authorize', 'billing', 'support', 'alert', 'suspended',
]

PHISH_LEGIT_LOOKALIKE = [
    'paypa1', 'rn1crosoft', 'arnazon', 'g00gle', 'facebok',
    'app1e', 'netfl1x', 'linkedln', 'tw1tter', 'instagramm',
    'dropb0x', 'sp0tify', 'youtu8e', 'gma1l', 'out1ook',
]

PHISH_RANDOM_WORDS = [
    'secure', 'safe', 'official', 'verified', 'trusted', 'protected',
    'encrypted', 'private', 'authentic', 'real', 'genuine', 'valid',
    'access', 'portal', 'center', 'service', 'online', 'web',
    'help', 'support', 'info', 'data', 'user', 'customer',
]

PHISH_PATHS = [
    '/login', '/signin', '/account/verify', '/account/login',
    '/secure/login', '/secure/verify', '/auth/signin',
    '/users/login?redirect=home', '/portal/access',
    '/paypal/login.php', '/amazon/account.php', '/google/signin.php',
    '/microsoft/update.php', '/apple/id/verify.php',
    '/banking/secure?session=verify&redirect=dashboard',
    '/verify?token=abc123&user=victim&action=confirm',
    '/update?account=suspended&action=recover&token=xyz',
    '/billing/confirm?invoice=12345&amount=99.99',
    '/password/reset?uid=12345&token=resettoken',
    '/login.html', '/signin.html', '/verify.html', '/update.html',
    '/wp-admin/login', '/admin/login', '/phpmyadmin/',
]


def random_ip():
    return '.'.join(str(random.randint(1, 255)) for _ in range(4))


def random_subdomain_chain(depth=None):
    if depth is None:
        depth = random.randint(2, 4)
    parts = [random.choice(PHISH_BRANDS)] + [random.choice(PHISH_ACTIONS) for _ in range(depth - 1)]
    random.shuffle(parts)
    return '.'.join(parts)


def make_phishing_url():
    strategy = random.randint(1, 8)

    if strategy == 1:
        # IP-based URL
        ip = random_ip()
        path = random.choice(PHISH_PATHS)
        scheme = random.choice(['http://', 'https://'])
        return f"{scheme}{ip}{path}"

    elif strategy == 2:
        # Brand + suspicious TLD
        brand = random.choice(PHISH_BRANDS)
        action = random.choice(PHISH_ACTIONS)
        tld = random.choice(PHISH_SUSPICIOUS_TLDS)
        domain = f"{brand}-{action}{tld}"
        path = random.choice(PHISH_PATHS)
        return f"http://{domain}{path}"

    elif strategy == 3:
        # Subdomain abuse — brand.attacker.com
        brand = random.choice(PHISH_BRANDS)
        attacker = random.choice(['verify-account', 'secure-login', 'user-support',
                                   'account-help', 'customer-portal', 'security-check',
                                   'billing-update', 'password-reset', 'access-denied'])
        tld = random.choice(['.com', '.net', '.org', '.info', '.biz'] + PHISH_SUSPICIOUS_TLDS[:5])
        path = random.choice(PHISH_PATHS)
        return f"http://{brand}.{attacker}{tld}{path}"

    elif strategy == 4:
        # Lookalike domain
        lookalike = random.choice(PHISH_LEGIT_LOOKALIKE)
        tld = random.choice(['.com', '.net', '.org'] + PHISH_SUSPICIOUS_TLDS[:5])
        path = random.choice(PHISH_PATHS)
        return f"http://{lookalike}{tld}{path}"

    elif strategy == 5:
        # @ symbol trick
        brand = random.choice(PHISH_BRANDS)
        attacker_domain = f"attacker{random.randint(100, 999)}.com"
        path = random.choice(PHISH_PATHS)
        return f"http://{brand}.com@{attacker_domain}{path}"

    elif strategy == 6:
        # Very long URL with lots of query parameters
        brand = random.choice(PHISH_BRANDS)
        action = random.choice(PHISH_ACTIONS)
        tld = random.choice(PHISH_SUSPICIOUS_TLDS)
        domain = f"{brand}-{action}-secure{tld}"
        tokens = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=32))
        path = f"/verify?user=victim&token={tokens}&redirect=https://{brand}.com&action=confirm&session={tokens[:16]}"
        return f"http://{domain}{path}"

    elif strategy == 7:
        # Deep subdomain chain
        chain = random_subdomain_chain()
        tld = random.choice(['.com', '.net'] + PHISH_SUSPICIOUS_TLDS[:3])
        path = random.choice(PHISH_PATHS)
        attacker = f"attacker{random.randint(10, 999)}"
        return f"http://{chain}.{attacker}{tld}{path}"

    else:
        # HTTP with suspicious keywords and brand in path
        word1 = random.choice(PHISH_RANDOM_WORDS)
        word2 = random.choice(PHISH_RANDOM_WORDS)
        tld = random.choice(PHISH_SUSPICIOUS_TLDS)
        domain = f"{word1}-{word2}{tld}"
        brand = random.choice(PHISH_BRANDS)
        action = random.choice(PHISH_ACTIONS)
        path = f"/{brand}/{action}?confirm=true&session=active"
        return f"http://{domain}{path}"


# ---------------------------------------------------------------------------
# Main generation loop
# ---------------------------------------------------------------------------
def generate_dataset(n_legit=3000, n_phish=3000, output_path=None):
    if output_path is None:
        output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dataset.csv')

    feature_names = get_feature_names()
    rows = []

    print(f"Generating {n_legit} legitimate URLs...")
    legit_urls = [make_legitimate_url() for _ in range(n_legit)]

    print(f"Generating {n_phish} phishing URLs...")
    phish_urls = [make_phishing_url() for _ in range(n_phish)]

    all_urls = [(u, 0) for u in legit_urls] + [(u, 1) for u in phish_urls]
    random.shuffle(all_urls)

    print("Extracting features...")
    for url, label in tqdm(all_urls):
        try:
            feats = extract_features(url)
            row = {name: feats[name] for name in feature_names}
            row['url'] = url
            row['label'] = label
            rows.append(row)
        except Exception as e:
            print(f"  Skipping '{url}': {e}")

    df = pd.DataFrame(rows)
    cols = ['url'] + feature_names + ['label']
    df = df[cols]
    df.to_csv(output_path, index=False)
    print(f"\nDataset saved to: {output_path}")
    print(f"Total samples : {len(df)}")
    print(f"Legitimate    : {(df['label'] == 0).sum()}")
    print(f"Phishing      : {(df['label'] == 1).sum()}")
    return df


if __name__ == '__main__':
    generate_dataset()
