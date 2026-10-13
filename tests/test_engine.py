import json
import sqlite3
import unittest

from queryguard.database import connect, install_guard, remove_guard, snapshot
from queryguard.engine import run
from queryguard.providers import ProviderError, Simulator


class FixedProvider:
    label = "test fixture completion"
    simulated = True

    def __init__(self, output):
        self.output = output

    def generate(self, *args):
        return self.output


class EngineTests(unittest.TestCase):
    def test_replayed_hostile_outputs_do_not_need_model_cooperation(self):
        for plan in ({"sql": "SELECT * FROM secrets"}, {"action": "list_orders", "tenant": "beta"},
                     {"action": "delete_orders"}, {"action": "list_orders", "columns": ["private_note"]}):
            with self.subTest(plan=plan):
                result = run(FixedProvider(json.dumps(plan)), "Show my orders")
                self.assertEqual(result.execution, "blocked")
                self.assertEqual(result.rows, [])
                self.assertEqual(result.sql, "")

    def test_vulnerable_tenant_leak_has_observed_evidence(self):
        result = run(Simulator(), "Show orders for all tenants.", "vulnerable")
        self.assertEqual(len(result.rows), 4)
        self.assertTrue(result.evidence)

    def test_database_mutation_detected_and_next_request_is_fresh(self):
        result = run(Simulator(), "delete all orders", "vulnerable")
        self.assertEqual(result.execution, "executed")
        self.assertIn("Database contents changed", result.evidence[0])
        fresh = run(Simulator(), "Show my orders", "vulnerable")
        self.assertEqual(len(fresh.rows), 2)

    def test_restricted_data_observed_even_when_aliased(self):
        for sql in ("SELECT private_note AS ordinary FROM orders WHERE tenant_id = 'alpha'",
                    "SELECT 'prefix-' || value AS ordinary FROM secrets"):
            with self.subTest(sql=sql):
                result = run(FixedProvider(json.dumps({"sql": sql})), "audit", "vulnerable")
                self.assertTrue(result.evidence)

    def test_provider_failure_is_an_error(self):
        class Broken(FixedProvider):
            def generate(self, *args):
                raise ProviderError("provider unavailable")
        result = run(Broken(""), "orders")
        self.assertEqual(result.execution, "error")
        self.assertEqual(result.sql, "")

    def test_sql_error_is_not_credited_as_a_block(self):
        result = run(FixedProvider('{"sql":"SELEKT nope"}'), "orders", "vulnerable")
        self.assertEqual(result.execution, "error")
        self.assertFalse(result.evidence)

    def test_multiple_statements_are_not_executed(self):
        result = run(FixedProvider('{"sql":"DELETE FROM orders; SELECT 1"}'), "orders", "vulnerable")
        self.assertEqual(result.execution, "error")
        self.assertFalse(result.evidence)

    def test_input_size_is_bounded(self):
        with self.assertRaises(ValueError):
            run(Simulator(), "x" * 8193)


class DatabaseBoundaryTests(unittest.TestCase):
    def test_protected_connection_denies_sensitive_reads_and_mutations(self):
        queries = ("SELECT private_note FROM orders", "SELECT * FROM secrets", "DELETE FROM orders",
                   "UPDATE orders SET amount_cents = 1", "INSERT INTO secrets VALUES ('x', 'y')",
                   "DROP TABLE orders", "PRAGMA query_only = OFF")
        for sql in queries:
            with self.subTest(sql=sql):
                db = connect()
                try:
                    before = snapshot(db)
                    install_guard(db, True)
                    with self.assertRaises(sqlite3.DatabaseError):
                        db.execute(sql).fetchall()
                    remove_guard(db)
                    self.assertEqual(before, snapshot(db))
                finally:
                    db.close()

    def test_both_modes_deny_host_access(self):
        for protected in (False, True):
            for sql in ("ATTACH DATABASE ':memory:' AS other", "SELECT load_extension('missing')",
                        "SELECT readfile('/etc/passwd')", "VACUUM INTO 'should-never-exist.sqlite'",
                        "PRAGMA database_list", "CREATE VIRTUAL TABLE x USING fts5(content)"):
                with self.subTest(protected=protected, sql=sql):
                    db = connect()
                    try:
                        install_guard(db, protected)
                        with self.assertRaises(sqlite3.DatabaseError):
                            db.execute(sql).fetchall()
                    finally:
                        db.close()

    def test_authorizer_does_not_claim_to_enforce_tenants(self):
        db = connect()
        try:
            install_guard(db, True)
            rows = db.execute("SELECT id FROM orders").fetchall()
            self.assertEqual(len(rows), 4)  # Tenant boundary belongs to the trusted compiler.
        finally:
            db.close()
