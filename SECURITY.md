# Security Policy

## Reporting a vulnerability in siteaudit
Please open a private security advisory on GitHub (Security tab -> "Report a vulnerability")
rather than a public issue. Expect an acknowledgement within a few days.

## Responsible use
siteaudit sends a small number of ordinary HTTP requests (page fetches, an `Origin` header probe,
and GETs for well-known sensitive paths). **Only run it against systems you own or have explicit
written permission to test.** Unauthorized scanning may be illegal in your jurisdiction.
