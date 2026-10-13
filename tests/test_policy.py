import json
import unittest

from queryguard.database import connect
from queryguard.policy import Context, PolicyError, compile_plan, decode_object


class PolicyTests(unittest.TestCase):
    def query(self, plan, tenant="alpha"):
        sql, params = compile_plan(json.dumps(plan), Context(tenant))
        db = connect()
        try:
            return [dict(row) for row in db.execute(sql, params)]
        finally:
            db.close()

    def test_tenant_identity_is_applied_for_both_tenants(self):
        for tenant, ids in (("alpha", [101, 102]), ("beta", [201, 202])):
            with self.subTest(tenant=tenant):
                rows = self.query({"action": "list_orders"}, tenant)
                self.assertEqual([row["id"] for row in rows], ids)
                self.assertTrue(all(row["tenant_id"] == tenant for row in rows))
                self.assertTrue(all("private_note" not in row for row in rows))

    def test_totals_do_not_cross_tenants(self):
        self.assertEqual(self.query({"action": "order_totals"}),
                         [{"order_count": 2, "total_cents": 20000}])
        self.assertEqual(self.query({"action": "order_totals"}, "beta"),
                         [{"order_count": 2, "total_cents": 120000}])

    def test_customer_values_are_literal_data(self):
        for value in ("' OR 1=1 --", "'; DELETE FROM orders; --", "Ada' UNION SELECT 1 --", "💾", "\x00", "%", "_"):
            with self.subTest(value=value):
                self.assertEqual(self.query({"action": "list_orders", "customer": value}), [])
        self.assertEqual(self.query({"action": "list_orders", "customer": "O'Brien"})[0]["id"], 102)

    def test_filter_applies_to_aggregates(self):
        self.assertEqual(self.query({"action": "order_totals", "customer": "Ada"}),
                         [{"order_count": 1, "total_cents": 12500}])
        self.assertEqual(self.query({"action": "order_totals", "customer": "missing"}),
                         [{"order_count": 0, "total_cents": 0}])

    def test_limit_is_enforced(self):
        self.assertEqual(len(self.query({"action": "list_orders", "limit": 1})), 1)

    def test_untrusted_plan_cannot_expand_authority(self):
        for field, value in (("tenant", "beta"), ("sql", "SELECT * FROM secrets"),
                             ("columns", ["private_note"]), ("table", "secrets"),
                             ("where", "1=1"), ("__proto__", {})):
            with self.subTest(field=field), self.assertRaises(PolicyError):
                compile_plan(json.dumps({"action": "list_orders", field: value}), Context())

    def test_invalid_plans_fail_closed(self):
        plans = [{}, {"action": "delete_orders"}, {"action": []}, {"action": None}]
        plans += [{"action": "list_orders", "limit": value} for value in (True, False, 0, -1, 101, 1.5, "2", None)]
        plans += [{"action": "list_orders", "customer": value} for value in ([], {}, 1, True, "x" * 201)]
        for plan in plans:
            with self.subTest(plan=plan), self.assertRaises(PolicyError):
                compile_plan(json.dumps(plan), Context())

    def test_malformed_json_duplicate_keys_and_huge_outputs_rejected(self):
        for raw in ("not JSON", "[]", "null", "{} trailing", '{"action":"list_orders","action":"delete_orders"}',
                    '{"limit":NaN}', '{"limit":Infinity}', " " * 8193, "[" * 1500 + "]" * 1500):
            with self.subTest(raw=raw[:60]), self.assertRaises(PolicyError):
                decode_object(raw)

    def test_unknown_application_identity_rejected(self):
        with self.assertRaises(PolicyError):
            Context("alpha' OR 1=1 --")
