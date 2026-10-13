# Threat model

## Assets and intended access

An authenticated sales user can list public order fields and aggregate sales for their own tenant. Other tenants' orders, `private_note` and the synthetic `secrets` table are out of scope for that user. All user requests are read-only. The host filesystem and network are outside the SQL execution surface.

## Attacker control

An attacker controls the natural-language question and retrieved reference text. Model output is also treated as attacker-controlled at the protected application boundary. The attacker cannot change application code, fixture creation, query templates, the authorizer, or the trusted request context within an experiment.

The CLI operator can change `--tenant`, edit source files, or replace a provider. This operator is the experiment owner, not a remote attacker. This lab contains no authentication service; the CLI identity flag is not an authentication mechanism.

## Security boundaries

| Boundary | Vulnerable flow | Protected flow |
| --- | --- | --- |
| Model output to SQL | Generated SQL is executable after checking the JSON wrapper | Only a validated, restricted query plan is accepted |
| Tenant scope | Depends on generated SQL following a prompt | Added by trusted application code |
| Restricted fields/tables | Available in the synthetic fixture | Excluded by the compiler and database authorizer |
| Writes | Permitted against fixture tables | No write action; query-only connection and authorizer |
| Customer values | Canned vulnerable completion demonstrates unsafe interpolation | Parameter binding preserves literal data |
| Host access | Restricted authorizer and disposable database | Same containment plus stricter read policy |

## Claims supported by the tests

- The supplied simulator cases expose six observable boundary violations in vulnerable mode.
- The protected path rejects the supplied unauthorized plans, treats customer payloads literally, and preserves the authorized baseline.
- Tenant filtering comes from application context even if a hostile provider tries to include a tenant override.
- The configured database guard denies the tested private reads, mutations, attachment and extension-loading attempts.
- A failed provider call or malformed SQL does not become a reported successful defense.

## Limits and non-goals

- A scripted simulator cannot establish whether any real model is susceptible. Its branch rules deliberately produce illustrative bad completions.
- Fixed fixture canaries can miss encoded or transformed leaks, aggregates, aliases that overwrite result keys, timing channels, and disclosures outside this dataset. A coincidental canary value can also mislead a general-purpose interpretation. Do not reuse these checks as a production data-loss detector.
- One run of nine cases is not an exhaustive assessment. Absence of findings is not proof of security.
- The two flows have different output contracts and prompts. This is an architecture comparison, not a controlled measurement of one prompt-only defense.
- The database authorizer has no row-level tenant knowledge. Removing the compiler's tenant predicate would remove tenant isolation. The tests explicitly demonstrate this distinction.
- SQLite and the Python process are trusted; this project does not attempt OS process isolation or defend against vulnerabilities in the SQLite engine itself.
- There is no arbitrary-target scanner, crawler, credential tester, public endpoint, production database integration, or persistent storage.
- Token costs, latency benchmarking, concurrent load, authentication/session attacks, application authorization roles, and provider/model supply-chain security are not evaluated.

To evolve the project, add cases with explicit observable oracles, richer role policies, and repeatable live-model evaluations. Keep real-model findings separate from simulator fixtures.
