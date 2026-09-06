import re
import json
import os
from datetime import datetime


SUSPICIOUS_PATTERNS = [
    r'<script.*?>.*?</script>',
    r'javascript:',
    r'on\w+\s*=',
    r'(\bSELECT\b.*\bFROM\b)|(\bINSERT\b)|(\bUPDATE\b)|(\bDELETE\b)',
]

def is_safe(text):
    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, text, re.IGNORECASE | re.DOTALL):
            return False
    return True

# ---------- Regex Patterns ----------
EMAIL_PATTERN = re.compile(r'''
    (?:[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*
    | "(?:[^\\"]|\\.)*")
    @
    (?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+
    [a-zA-Z]{2,}
''', re.VERBOSE)

ALU_DOMAINS = {
    'official': 'alueducation.com',
    'alumni': 'alumni.alueducation.com',
    'si': 'si.alueducation.com'
}

URL_PATTERN = re.compile(r'''
    (?:https?://|ftp://|www\.)
    [a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+
    (?:/[^\s<>"']*)?
''', re.VERBOSE | re.IGNORECASE)

PHONE_PATTERN = re.compile(r'''
    (?:\(?(\d{3})\)?[-.\s]?)?
    (\d{3})[-.\s]?
    (\d{4})
    (?:ext\.?\s*(\d+))?
''', re.VERBOSE)

CC_PATTERN = re.compile(r'''
    \b
    (?:4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}
    | 5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}
    | 3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}
    | 6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})
    \b
''', re.VERBOSE)

def validate_cc(cc):
    digits = re.sub(r'[-\s]', '', cc)
    if not digits.isdigit():
        return False
    def luhn_check(card):
        total = 0
        reverse = card[::-1]
        for i, d in enumerate(reverse):
            n = int(d)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0
    return luhn_check(digits)

# ---------- Extraction ----------
def extract_data(text):
    results = {
        'emails': [],
        'urls': [],
        'phones': [],
        'credit_cards': [],
        'alu_emails': {'official': [], 'alumni': [], 'si': []}
    }

    lines = text.splitlines()
    for line in lines:
        if not is_safe(line):
            print(f"Warning: Skipping suspicious line: {line[:50]}...")
            continue

        # Emails
        emails = EMAIL_PATTERN.findall(line)
        for email in emails:
            if '@' in email and '.' in email.split('@')[1]:
                results['emails'].append(email)
                for key, domain in ALU_DOMAINS.items():
                    if email.endswith('@' + domain):
                        results['alu_emails'][key].append(email)

        # URLs
        urls = URL_PATTERN.findall(line)
        results['urls'].extend(urls)

        # Phones
        phones = PHONE_PATTERN.findall(line)
        for match in phones:
            if match and match[0] and match[1] and match[2]:
                area = match[0]
                first3 = match[1]
                last4 = match[2]
                ext = match[3] if match[3] else ''
                full = f"({area}) {first3}-{last4}"
                if ext:
                    full += f" ext.{ext}"
                results['phones'].append(full)

        # Credit Cards
        cc_matches = CC_PATTERN.findall(line)
        for cc in cc_matches:
            if validate_cc(cc):
                redacted = '****-****-****-' + cc[-4:]
                results['credit_cards'].append({
                    'full': cc,
                    'redacted': redacted
                })

    return results

# ---------- Main ----------
def main():

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_path = os.path.join(base_dir, 'input', 'raw-text.txt')
    output_path = os.path.join(base_dir, 'output', 'sample-output.json')

    # Read input
    with open(input_path, 'r', encoding='utf-8') as f:
        raw_text = f.read()

    extracted = extract_data(raw_text)

    output = {
        'extraction_timestamp': datetime.now().isoformat(),
        'data': extracted
    }

    # Write output
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # Console summary
    print("=== Extraction Summary ===")
    print(f"Emails found: {len(extracted['emails'])}")
    for email in extracted['emails']:
        print(f"  - {email}")
    print(f"ALU official: {len(extracted['alu_emails']['official'])}")
    print(f"ALU alumni: {len(extracted['alu_emails']['alumni'])}")
    print(f"ALU si: {len(extracted['alu_emails']['si'])}")
    print(f"URLs found: {len(extracted['urls'])}")
    for url in extracted['urls']:
        print(f"  - {url}")
    print(f"Phones found: {len(extracted['phones'])}")
    for phone in extracted['phones']:
        print(f"  - {phone}")
    print(f"Credit cards found: {len(extracted['credit_cards'])}")
    for cc in extracted['credit_cards']:
        print(f"  - {cc['redacted']}")
    print(f"Results saved to: {output_path}")

if __name__ == '__main__':
    main()