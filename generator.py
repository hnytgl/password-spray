"""
Password generator for common enterprise patterns.

Template tokens:
  {Season}/{season}   Spring, Summer, Fall, Winter
  {Month}/{month}     January - December
  {Mon}/{mon}         Jan - Dec
  {Day}/{day}         01-31 / 1-31
  {Year}              Current year +/- 1 (4-digit)
  {YearNN}            Specific year e.g. {Year2024}
  {Special}           ! / @ / # / 123 / !! / 123! / etc.
  {Number}            0-99
  {NumberN}           0-N
  {Company}/{company} Custom company name
  {City}/{city}       Common city names
  {Word}/{word}       Password, Welcome, Admin, Company, etc.

Examples:
  {Season}{Year}{Special}   → Spring2024!, Summer2024!, ..., Winter2025!
  {Company}{Number}{Special} → Acme1!, Acme2!, ..., Acme99!
  {Mon}{Year}                → Jan2024, Feb2024, ..., Dec2025
"""

import itertools
import re
from datetime import datetime


SEASONS = ["Spring", "Summer", "Fall", "Winter"]
MONTHS = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
]
MONTHS_ABBR = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
]
COMMON_WORDS = [
    "Password", "Welcome", "Company", "Admin", "Changeme",
    "Qwerty", "Secret", "Master", "Summer", "Winter",
]
CITIES = [
    "London", "Paris", "Berlin", "NewYork", "Tokyo", "Sydney",
    "Moscow", "Dubai", "Beijing", "Chicago", "Dallas", "Atlanta",
    "Seattle", "Miami", "Boston", "Denver", "Austin", "Phoenix",
]
SPECIALS = [
    "!", "@", "#", "!!", "@@", "##", "123", "123!", "123456",
    "1", "!", "!!", "!@#", "2024!", "2025!", "2026!",
]


def _build_parts(company, year):
    if year is None:
        year = datetime.now().year

    def _year_range():
        for y in range(year - 1, year + 2):
            yield str(y)

    return {
        "{Season}":   SEASONS,
        "{season}":   [s.lower() for s in SEASONS],
        "{Month}":    MONTHS,
        "{month}":    [m.lower() for m in MONTHS],
        "{Mon}":      MONTHS_ABBR,
        "{mon}":      [m.lower() for m in MONTHS_ABBR],
        "{Day}":      [f"{d:02d}" for d in range(1, 32)],
        "{day}":      [str(d) for d in range(1, 32)],
        "{Year}":     list(_year_range()),
        "{Special}":  SPECIALS,
        "{Number}":   [str(n) for n in range(100)],
        "{Word}":     COMMON_WORDS,
        "{word}":     [w.lower() for w in COMMON_WORDS],
        "{City}":     CITIES,
        "{city}":     [c.lower() for c in CITIES],
        "{Company}":  [company] if company else ["Company"],
        "{company}":  [company.lower()] if company else ["company"],
    }


def _custom_number_token(token):
    """Parse {NumberN} → 0..N  or  {YearNNNN} → single year."""
    m = re.match(r"\{Number(\d+)\}", token)
    if m:
        limit = int(m.group(1))
        return [str(n) for n in range(limit + 1)]

    m = re.match(r"\{Year(\d{4})\}", token)
    if m:
        return [m.group(1)]

    return None


def _split_template(template, parts):
    """Split a template string into alternating literal / token segments."""
    token_re = "|".join(re.escape(k) for k in parts)
    # Also catch {NumberN} and {YearNNNN}
    custom_re = r"\{Number\d+\}|\{Year\d{4}\}"
    combined = f"{token_re}|{custom_re}" if token_re else custom_re
    if not combined:
        return [([template], True)]  # all literal

    segments = []
    pos = 0
    for m in re.finditer(combined, template):
        if m.start() > pos:
            segments.append(([template[pos:m.start()]], True))
        token = m.group()
        custom = _custom_number_token(token)
        if custom:
            segments.append((custom, False))
        else:
            segments.append((parts.get(token, [token]), False))
        pos = m.end()

    if pos < len(template):
        segments.append(([template[pos:]], True))

    return segments


def generate(template, company="", year=None, max_combinations=50000):
    """Generate password list from a template string.

    Args:
        template:  e.g. "{Season}{Year}{Special}"
        company:   company name for {Company} token
        year:      base year for {Year} (default: current year)
        max_combinations: safety cap to avoid accidental 10M-word lists

    Returns:
        list of password strings
    """
    parts = _build_parts(company, year)
    segs = _split_template(template, parts)

    total = 1
    for values, _ in segs:
        total *= len(values)
        if total > max_combinations:
            raise ValueError(
                f"Template '{template}' would generate {total:,}+ "
                f"passwords (limit: {max_combinations:,}). "
                f"Use a more specific template or raise --max-combinations."
            )

    results = [""]
    for values, _ in segs:
        results = [r + v for r in results for v in values]

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for pw in results:
        if pw not in seen:
            seen.add(pw)
            unique.append(pw)
    return unique


def generate_multi(templates, company="", year=None):
    """Generate passwords from multiple templates and merge the results."""
    all_passwords = []
    for tmpl in templates:
        all_passwords.extend(generate(tmpl, company=company, year=year))
    return list(dict.fromkeys(all_passwords))
