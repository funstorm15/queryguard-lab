# Security scope

QueryGuard Lab intentionally contains a vulnerable execution mode operating on synthetic, disposable data. Findings against that mode are expected teaching outcomes.

Unexpected access through the protected flow, host filesystem access from generated SQL, unsafe report rendering, or secret leakage from provider configuration would be security defects. Report a minimal reproduction with synthetic data to the repository maintainer. If the repository has GitHub private vulnerability reporting enabled, use that channel for a host-containment or protected-flow issue.

Do not include credentials, personal data, or private customer records in an issue. The maintainer should enable private vulnerability reporting when publishing the repository.
