# Google Mail Analyzer

A Python script to analyze Google Takeout mbox files and generate statistics about your email senders. It separates regular senders from spam/advertising senders using sophisticated content analysis.

## Features

- Parses mbox format email archives from Google Takeout
- **Spam Detection**: Automatically categorizes senders as regular or spam/advertising
  - Domain-based filtering (known marketing platforms)
  - Content keyword analysis (150+ spam keywords)
  - Email header analysis (mailing list flags, precedence, priority)
  - Adjustable sensitivity threshold
- Counts and ranks senders by email frequency
- Filters out automated/no-reply addresses (optional)
- Displays sender names along with email addresses
- Progress tracking during analysis
- Shows spam detection keywords for debugging

## Requirements

- Python 3.6 or higher
- No external dependencies (uses Python standard library only)

## Installation

No installation required. Simply download the script:

```bash
# Clone or download the script
git clone <repository-url>
cd googleMail
```

## Usage

### Basic Usage

Analyze an mbox file and show top 50 regular senders and top 100 spam senders:

```bash
python3 analyze_mbox.py /path/to/your/file.mbox
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `--include-no-reply` | Include automated/no-reply addresses in results |
| `--top N` | Show top N regular senders (default: 50) |
| `--top-spam N` | Show top N spam senders (default: 100) |
| `--spam-threshold N` | Spam detection sensitivity (default: 5). Higher = less sensitive, Lower = more sensitive |
| `--show-spam-keywords` | Show which keywords triggered spam detection for each sender |

### Examples

```bash
# Basic analysis
python3 analyze_mbox.py "All mail Including Spam and Trash.mbox"

# Include no-reply addresses
python3 analyze_mbox.py "All mail Including Spam and Trash.mbox" --include-no-reply

# Show top 100 regular and 200 spam senders
python3 analyze_mbox.py "All mail Including Spam and Trash.mbox" --top 100 --top-spam 200

# Make spam detection more aggressive (lower threshold)
python3 analyze_mbox.py "All mail Including Spam and Trash.mbox" --spam-threshold 3

# Make spam detection less aggressive (higher threshold)
python3 analyze_mbox.py "All mail Including Spam and Trash.mbox" --spam-threshold 8

# Show which keywords triggered spam detection
python3 analyze_mbox.py "All mail Including Spam and Trash.mbox" --show-spam-keywords
```

## Getting Your Mbox File

1. Go to [Google Takeout](https://takeout.google.com/)
2. Select "Mail" and deselect all other services
3. Choose "Mbox" as the format
4. Create your export
5. Download and extract the zip file
6. Run the script on the `.mbox` file

## Output Example

```
======================================================================
TOP 50 REGULAR SENDERS
======================================================================
 1234  John Smith                            <john.smith@example.com>
  987  Sarah Johnson                         <sarah.j@company.com>
  756  Mom                                   <mom@email.com>
  ...

======================================================================
TOP 100 SPAM/ADVERTISING SENDERS
======================================================================
 2456  Amazon                                <ship-confirm@amazon.com>
 1890  Newsletter                            <news@newsletter.com>
 1234  Promo Deals                           <deals@store.com>
  ...

======================================================================
SUMMARY
======================================================================
Total unique regular senders: 245
Total regular emails: 5432
Total unique spam senders: 89
Total spam/advertising emails: 8765
Spam percentage: 61.7%
======================================================================
```

## Spam Detection

The script uses multiple methods to detect spam and advertising emails:

### 1. Domain-Based Filtering

Known marketing and automation platforms are flagged:
- Mailchimp, SendGrid, Mailgun, Amazon SES
- Constant Contact, HubSpot, ActiveCampaign
- And many more (40+ domains)

### 2. Keyword Analysis

Emails are scanned for 150+ spam keywords including:
- **Marketing terms**: coupon, promo code, discount, sale, deal
- **Urgency phrases**: expires soon, last chance, act now, hurry
- **Newsletter indicators**: unsubscribe, opt-out, weekly digest
- **Financial scams**: bitcoin, crypto, get rich quick, work from home

### 3. Header Analysis

Email headers are checked for:
- `List-Unsubscribe` or `List-Id` headers (mailing lists)
- `Precedence: bulk` or `Precedence: junk`
- `X-Priority: 1` or `Priority: urgent` from unknown senders

### 4. Scoring System

Each spam indicator adds points to the email's score. If the score meets or exceeds the threshold, it's classified as spam:
- Domain match: +3 points
- Suspicious subdomain: +2 points
- Subject keyword match: +2 points
- Body keyword match: +1 point
- Mailing list header: +2 points
- Bulk/junk precedence: +2 points
- High priority header: +1 point

**Default threshold: 5** (adjustable with `--spam-threshold`)

## Filtered Patterns

By default, the following automated patterns are filtered out:

- `no-reply`, `noreply`, `no_replay`, `donotreply`
- `notification`, `notifications`, `notify`
- `auto-reply`, `auto`, `mailer`, `daemon`
- `bounce`, `postmaster`, `support@`, `info@`
- `notifications@`, `alerts@`, `noreply@`
- `-noreply@`, `@do-not-reply`, `@donotreply`
- `digest`, `digests`

Use `--include-no-reply` to disable this filtering.

## License

MIT License
