# Contributing

Bug reports, clearer examples, and new test cases are welcome. Start with a small change that someone else can reproduce using the fake dataset.

Before submitting it, run:

```bash
python3 -m unittest discover -s tests -v
python3 -m queryguard scan
```

Ordinary requests should still work, and the protected cases should have no violations, errors, or unexplained results.

## Adding a case

Add the input and expected behavior to `queryguard/cases.py`. Explain what would count as a real failure: a private value appearing in the result, a row from another tenant, or a change to the database. Test that observation as well as the protected behavior.

If the example needs a simulator branch, label it as scripted. Keep real-model findings separate. Update the threat model if your check has a new blind spot, and regenerate the example reports when expected results change.

## Reporting a bug

Include the command or UI steps, Python version, provider/model name, case ID, and result you expected. Use synthetic data in the reproduction. A failure in the deliberately vulnerable mode is usually part of the example; an unexpected failure in protected mode or host containment needs investigation.

Keep the offline demo free of runtime dependencies where possible. Changes to the SQL compiler or database authorizer need tests for the specific permission they enforce. Prompt wording alone should never decide access.
