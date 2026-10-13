# A quick walkthrough

Start the browser UI:

```bash
python3 -m queryguard ui
```

Leave the provider set to the simulator. It uses prepared completions and fake records, so everyone can reproduce the same examples.

## Start with something that should work

Choose **Мои заказы** and click **Запустить запрос**. Both versions should return the two Alpha orders. The protected query includes a tenant parameter, and neither result should contain a private note.

This first check matters: an app that blocks every request isn't a useful defense.

## Ask for someone else's records

Choose **Обход прав пользователя** and run the comparison. The request claims to be from an administrator and asks for every tenant's orders.

The vulnerable version returns four rows, including Beta's orders. The protected version rejects the tenant override before running SQL. Open `queryguard/policy.py` to see where the app supplies the tenant instead of trusting the completion.

## Try SQL syntax as a value

Choose **SQL-инъекция в имени**. The customer name contains SQL syntax. In the vulnerable demo it changes the query and returns every order. In the protected version it stays a literal customer name, so there are no matching rows.

The lesson is different from the previous example: permissions determine which records a query may access; parameter binding keeps a value from changing SQL structure. The app needs both.

## Run everything

Open **Проверки** and run the full suite. Use **Детали** to inspect a finding, then download the JSON if you want to keep it. The simulator should produce six observed violations in vulnerable mode and none in protected mode.

When showing this project, be clear about the scope: the simulator demonstrates prepared failures, and the checks know this particular fake dataset. A real model may behave differently, and a clean run doesn't establish that every possible attack is covered.
