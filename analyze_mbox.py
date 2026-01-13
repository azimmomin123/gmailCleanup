#!/usr/bin/env python3
"""
Analyze a Google Takeout mbox file to count emails by sender.
Run this script locally: python3 analyze_mbox.py /path/to/your/file.mbox
"""

import mailbox
import email
from email.utils import getaddresses, parseaddr
from collections import Counter
import sys
import re


# Spam and advertising detection patterns
SPAM_KEYWORDS = [
    # Marketing/Coupon terms
    'coupon', 'promo code', 'discount code', 'voucher', 'deal', 'save %',
    'limited time', 'act now', 'exclusive offer', 'special promotion',
    'free gift', 'bonus', 'reward', 'cash back', 'earn points',
    '% off', 'percent off', 'dollar off', 'price drop',

    # Urgency/Call-to-action
    'urgent', 'expires soon', 'last chance', 'don\'t miss', 'only today',
    'click here', 'unsubscribe', 'opt-out', 'sale ends', 'today only',
    'ending soon', 'hurry', 'time is running out', 'deadline approaching',

    # Common spam phrases
    'you\'ve been selected', 'congratulations', 'winner', 'claim now',
    'verify your account', 'suspicious activity', 'your payment',
    'you have won', 'selected randomly', 'exclusive access',

    # Financial/Scam
    'bitcoin', 'crypto', 'investment opportunity', 'make money',
    'work from home', 'get rich', 'financial freedom', 'passive income',
    'earn extra cash', 'quick cash', 'easy money',

    # Product spam
    'buy now', 'order today', 'free shipping', 'add to cart',
    'shop now', 'clearance', 'liquidation', 'flash sale',
    'mega sale', 'blowout sale', 'stock up', 'while supplies last',

    # Newsletter/Marketing
    'newsletter', 'weekly digest', 'daily deals', 'special offers',
    'promotional', 'marketing', 'advertisement', 'sponsored',
    'you may also like', 'recommended for you', 'because you viewed',
]

# Known spam/advertising domains (marketing platforms, bulk senders)
SPAM_DOMAINS = [
    # Marketing automation platforms
    'mailchimp.com', 'campaign-monitor.com', 'constantcontact.com',
    'sendgrid.com', 'sendgrid.net', 'mailgun.com', 'mailgun.org',
    'amazonses.com', 'sparkpostmail.com', 'sparkpost.com',
    'getresponse.com', 'aweber.com', 'convertkit.com', 'convertkit.mail',
    'activehosted.com', 'activecampaign.com', 'omnisend.com',
    'hubspot-email.com', 'hubspotmail.com', 'hubspot.com',
    'elasticemail.com', 'mailchimpapp.com', 'mcdlv.net', 'mcdlv.net',
    'bounces.mailchimp.com', 'list-manage.com', 'list-manage.com',

    # Retail/promotional domains (add more as needed)
    'promos.', 'deals.', 'sale.', 'news.', 'marketing.', 'promo.',
    'e-merchant', 'ecommerce-', 'shop.', 'store.', 'orders.',
]

# Threshold for spam detection (higher = less sensitive)
SPAM_THRESHOLD = 5


def extract_sender(msg):
    """Extract the sender's email address from a message."""
    from_header = msg.get('From', '')
    # Parse the From header to get just the email address
    name, addr = parseaddr(from_header)
    return addr.lower() if addr else None


def extract_display_name(msg):
    """Extract the sender's display name from a message."""
    from_header = msg.get('From', '')
    name, addr = parseaddr(from_header)
    return name if name else addr


def is_no_reply(email_addr):
    """Check if this is a no-reply or automated address."""
    no_reply_patterns = [
        'no-reply', 'noreply', 'no_replay', 'donotreply',
        'notification', 'notifications', 'notify',
        'auto-reply', 'auto', 'mailer', 'daemon',
        'bounce', 'postmaster', 'support@', 'info@',
        'notifications@', 'alerts@', 'noreply@',
        '-noreply@', '@do-not-reply', '@donotreply',
        'digest', 'digests'
    ]
    email_lower = email_addr.lower()
    return any(pattern in email_lower for pattern in no_reply_patterns)


def get_sender_domain(email_addr):
    """Extract the domain from an email address (part after @)."""
    if '@' not in email_addr:
        return None
    return email_addr.split('@')[-1].lower()


def is_spam_content(msg, sender_email, threshold=SPAM_THRESHOLD):
    """
    Analyze full email to determine if it's spam/advertising.

    Returns a tuple: (is_spam: bool, score: int, matched_keywords: list)
    """
    score = 0
    matched_keywords = []

    # 1. Check sender domain
    domain = get_sender_domain(sender_email)
    if domain:
        # Check for exact domain match
        for spam_domain in SPAM_DOMAINS:
            if domain == spam_domain or domain.endswith('.' + spam_domain.lstrip('.')):
                score += 3
                matched_keywords.append(f"domain:{domain}")
                break

        # Check for suspicious subdomain patterns
        if any(domain.startswith(prefix) for prefix in ['promo', 'deals', 'news', 'marketing', 'shop', 'store', 'ecommerce', 'mail', 'email']):
            score += 2
            matched_keywords.append(f"suspicious-subdomain:{domain}")

    # 2. Check subject line
    subject = str(msg.get('Subject', '')).lower()
    for keyword in SPAM_KEYWORDS:
        if keyword in subject:
            score += 2
            if f"subject:{keyword}" not in matched_keywords:
                matched_keywords.append(f"subject:{keyword}")

    # 3. Check email body (if available)
    body_text = ""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain' or content_type == 'text/html':
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text += payload.decode('utf-8', errors='ignore').lower()
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body_text = payload.decode('utf-8', errors='ignore').lower()

        # Check body for keywords (with a limit to avoid false positives)
        for keyword in SPAM_KEYWORDS:
            if keyword in body_text:
                score += 1
                if f"body:{keyword}" not in matched_keywords:
                    matched_keywords.append(f"body:{keyword}")
    except Exception:
        # If we can't decode the body, skip it
        pass

    # 4. Check for mailing list headers
    if msg.get('List-Unsubscribe') or msg.get('List-Id'):
        score += 2
        matched_keywords.append("mailing-list")

    # 5. Check for bulk/junk precedence
    precedence = str(msg.get('Precedence', '')).lower()
    if precedence in ['bulk', 'junk']:
        score += 2
        matched_keywords.append(f"precedence:{precedence}")

    # 6. Check for common spam headers
    if msg.get('X-Priority') == '1' or msg.get('Priority') == 'urgent':
        # High priority from unknown senders is often spam
        score += 1
        matched_keywords.append("high-priority")

    return score >= threshold, score, matched_keywords


def analyze_mbox(mbox_path, exclude_no_reply=True, top_n=50, top_spam=100, spam_threshold=SPAM_THRESHOLD, show_spam_keywords=False):
    """
    Analyze mbox file and count emails by sender.

    Separates emails into regular and spam/advertising categories.
    """
    print(f"Opening {mbox_path}...")
    mbox = mailbox.mbox(mbox_path)

    total_messages = len(mbox)
    print(f"Found {total_messages} messages. Analyzing...\n")

    # Track regular and spam senders separately
    regular_senders = Counter()
    spam_senders = Counter()
    senders_with_names = {}
    spam_sender_keywords = {}  # Track which keywords triggered spam detection

    for i, msg in enumerate(mbox):
        if i % 1000 == 0:
            print(f"Processing... {i}/{total_messages}")

        sender = extract_sender(msg)
        if sender:
            # Skip no-reply addresses if requested
            if exclude_no_reply and is_no_reply(sender):
                continue

            # Check if this is spam/advertising content
            is_spam, score, keywords = is_spam_content(msg, sender, spam_threshold)

            if is_spam:
                spam_senders[sender] += 1
                if sender not in spam_sender_keywords:
                    spam_sender_keywords[sender] = set()
                spam_sender_keywords[sender].update(keywords)
            else:
                regular_senders[sender] += 1

            # Store display name if not already stored
            if sender not in senders_with_names:
                senders_with_names[sender] = extract_display_name(msg)

    # Print regular senders section
    print("\n" + "="*70)
    print(f"TOP {top_n} REGULAR SENDERS")
    print("="*70)

    for email_addr, count in regular_senders.most_common(top_n):
        name = senders_with_names.get(email_addr, email_addr)
        print(f"{count:5d}  {name:40s} <{email_addr}>")

    # Print spam/advertising senders section
    print("\n" + "="*70)
    print(f"TOP {top_spam} SPAM/ADVERTISING SENDERS")
    print("="*70)

    for email_addr, count in spam_senders.most_common(top_spam):
        name = senders_with_names.get(email_addr, email_addr)
        domain = get_sender_domain(email_addr)
        if show_spam_keywords and email_addr in spam_sender_keywords:
            # Show top few keywords that triggered spam detection
            keywords_str = ", ".join(list(spam_sender_keywords[email_addr])[:3])
            print(f"{count:5d}  {name:40s} <{email_addr}> [{keywords_str}]")
        else:
            print(f"{count:5d}  {name:40s} <{email_addr}>")

    # Print summary statistics
    total_regular = sum(regular_senders.values())
    total_spam = sum(spam_senders.values())
    total_analyzed = total_regular + total_spam

    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Total unique regular senders: {len(regular_senders)}")
    print(f"Total regular emails: {total_regular}")
    print(f"Total unique spam senders: {len(spam_senders)}")
    print(f"Total spam/advertising emails: {total_spam}")
    if total_analyzed > 0:
        print(f"Spam percentage: {100 * total_spam / total_analyzed:.1f}%")
    print("="*70)

    return regular_senders, spam_senders


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_mbox.py /path/to/your/file.mbox")
        print("\nOptional arguments:")
        print("  --include-no-reply        Include automated/no-reply addresses")
        print("  --top N                   Show top N regular senders (default: 50)")
        print("  --top-spam N              Show top N spam senders (default: 100)")
        print("  --spam-threshold N        Spam detection threshold (default: 5)")
        print("                            Higher = less sensitive, Lower = more sensitive")
        print("  --show-spam-keywords      Show which keywords triggered spam detection")
        sys.exit(1)

    mbox_path = sys.argv[1]
    exclude_no_reply = "--include-no-reply" not in sys.argv
    show_spam_keywords = "--show-spam-keywords" in sys.argv

    top_n = 50
    top_spam = 100
    spam_threshold = SPAM_THRESHOLD

    for i, arg in enumerate(sys.argv):
        if arg == "--top" and i + 1 < len(sys.argv):
            try:
                top_n = int(sys.argv[i + 1])
            except ValueError:
                pass
        elif arg == "--top-spam" and i + 1 < len(sys.argv):
            try:
                top_spam = int(sys.argv[i + 1])
            except ValueError:
                pass
        elif arg == "--spam-threshold" and i + 1 < len(sys.argv):
            try:
                spam_threshold = int(sys.argv[i + 1])
            except ValueError:
                pass

    try:
        analyze_mbox(mbox_path, exclude_no_reply, top_n, top_spam, spam_threshold, show_spam_keywords)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
