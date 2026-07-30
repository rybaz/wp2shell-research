"""wp2shell — research PoC for CVE-2026-63030 + CVE-2026-60137.

WordPress REST batch handler-permission desync (63030) chained, via a nested
batch, into a WP_Query author__not_in SQL injection (60137) for unauthenticated
database read. For authorized security research only.
"""

__version__ = "2.0.0"
