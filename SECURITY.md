# Security

Never attach authentication state, callback URLs, cookies, resource tickets,
organization policy exports, private keys or passwords to public issues.

Use only resources you are authorized to access. Keep gateway trust explicit,
keep private state under your account's access controls, and avoid exposing
the unauthenticated local proxy to other users.

This is experimental software. Long-lived session renewal, immediate policy
revocation, additional authentication challenges and transport extensions need
further validation. Report reproducible bugs with sanitized version information,
configuration structure and error codes only.
