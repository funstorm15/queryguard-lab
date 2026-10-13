# Architecture

## Browser interface

`python -m queryguard ui` serves packaged assets and a small JSON API on loopback only. It uses the same provider, execution engine and case oracles as the CLI. Built-in case requests use server-owned prompts and expected results.

POST requests require an allowed Host, matching local Origin, bounded JSON body and random per-server token. Only one experiment runs at a time. There is no arbitrary file serving or CORS access. Untrusted outputs are rendered with `textContent`, and responses include a restrictive content security policy. This is not an authenticated multi-user service; do not reverse-proxy it onto a public host.

The browser stores results in tab memory and exports a separate `ui_session_version: 1` JSON format. It accepts no database paths or external targets. Generated SQL executes only within the existing contained fixture mode.

## Request flow

`cli.main` selects the provider, trusted experimental tenant and case set. `scanner.scan` runs each case once per selected mode. Each call to `engine.run` generates a completion, validates it, creates a new in-memory fixture, installs the appropriate database authorizer, executes one statement, observes its effects, and closes the database.

SQL errors cannot contaminate later experiments. The connection is never reused across cases. Schema and seed data are application-controlled. No database connection string or file path is accepted.

## Provider contract

Providers implement:

```python
class Provider:
    label: str
    simulated: bool

    def generate(self, prompt, mode, context, retrieved_context="") -> str:
        ...
```

The return value is untrusted text. Providers should raise `ProviderError` for expected transport/generation failures. A programming error in a custom provider is intentionally not silently reclassified as a successful defense.

The simulator returns scripted illustrative completions. Ollama supplies actual generated text, using separate system instructions for the two output contracts. Its HTTP response is capped at 64 KiB; completion text is capped at 8,192 characters by the validator. A fixed seed and temperature reduce variation without promising determinism.

To add a provider, implement this interface, expose its selection in the CLI, add transport/error tests, and record its model identity in `label`. Keep `simulated=False` for actual model calls. Do not add external database targets as part of a provider adapter.

## Protected query contract

Allowed fields are `action`, `customer`, and `limit`. Unknown fields, duplicate JSON keys, non-finite JSON literals, wrong types and unsupported actions are rejected. `limit` is an integer from 1 to 100; booleans are deliberately rejected despite Python's integer subclassing. `customer` is null or at most 200 characters. SQL-like text in a customer value is valid literal data, not a reason to reject the request.

`list_orders` returns approved fields ordered by ID and applies the limit. `order_totals` returns one count/sum row; a validated `limit` has no effect on that single aggregate row. Both actions bind the application tenant and optional customer as parameters.

The only interpolated SQL components come from internal constants. No model-controlled field becomes a SQL identifier or expression. The model never creates an executable predicate.

## Database boundary

Protected execution enables SQLite `query_only` and an authorizer allowing SELECT, reads of approved order columns, and the small aggregate function set. It denies secret-table/private-note access, writes, schema changes, attachment, pragmas and all other authorizer actions.

Vulnerable execution permits reads and mutations of the two synthetic fixture tables. Host-containment restrictions still deny attachment, virtual tables, extension loading, schema operations, arbitrary SQL functions and pragmas. The code executes one SQL statement, not a script. Statement caching is disabled so every preparation goes through the current authorizer.

Both modes limit SQL length, SQLite value size, column count and returned rows. A progress callback interrupts queries after approximately 100,000 virtual-machine instructions. These are bounded lab safeguards, not a complete resource-isolation solution for a public service.

Trusted observation removes the authorizer/progress callback after execution, then compares complete fixture contents. This is internal code, not a capability available to the model. The protected connection remains query-only. The connection is closed after observation, including when execution fails.

See the Python standard library's [parameter binding guidance](https://docs.python.org/3/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries) and [authorizer API](https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.set_authorizer) for the underlying interfaces.

## Evidence and reporting

Known fixture identifiers and private canaries identify covered disclosure classes. Snapshot changes identify unauthorized mutation. Legitimate cases use exact expected-row oracles, independently queried from a fresh fixture. The attack outcomes remain conservative: no observable exposure is `not_observed`, and an unexplained mismatch is `inconclusive`.

JSON reports include schema/tool versions, timestamp, provider, simulator status, scope, limitations, per-mode counts, and all case evidence. HTML renders the same findings with escaped text and a restrictive content security policy. It has no JavaScript, network requests, or external styles/fonts.

Reports contain full prompts and returned synthetic records. If you supply your own reference text to `ask`, that content appears in the output. Do not put real credentials or private records into this educational fixture.
