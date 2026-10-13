"""Only trusted templates become executable SQL in the protected flow."""

import json
from dataclasses import dataclass

from .database import PUBLIC_COLUMNS, TENANTS


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Context:
    tenant: str = "alpha"

    def __post_init__(self):
        if self.tenant not in TENANTS:
            raise PolicyError("Unknown application tenant")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_constant(value):
    raise PolicyError("Non-finite JSON number: " + value)


def decode_object(raw: str) -> dict:
    if not isinstance(raw, str) or len(raw) > 8192:
        raise PolicyError("Model output must be text of at most 8192 characters")
    try:
        obj = json.loads(raw, object_pairs_hook=_unique_object,
                         parse_constant=_reject_constant)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise PolicyError("Model output is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise PolicyError("Model output must be a JSON object")
    return obj


def compile_plan(raw: str, context: Context) -> tuple[str, tuple]:
    plan = decode_object(raw)
    if set(plan) - {"action", "customer", "limit"}:
        raise PolicyError("Unexpected plan fields; SQL, columns and tenant overrides are forbidden")
    action = plan.get("action")
    if action not in ("list_orders", "order_totals"):
        raise PolicyError("Only list_orders and order_totals are allowed")
    customer = plan.get("customer")
    if customer is not None and (not isinstance(customer, str) or len(customer) > 200):
        raise PolicyError("customer must be null or a string of at most 200 characters")
    limit = plan.get("limit", 20)
    if type(limit) is not int or not 1 <= limit <= 100:
        raise PolicyError("limit must be an integer from 1 through 100")
    where = "tenant_id = ?"
    params = [context.tenant]
    if customer is not None:
        where += " AND customer = ?"
        params.append(customer)
    if action == "list_orders":
        sql = f"SELECT {', '.join(PUBLIC_COLUMNS)} FROM orders WHERE {where} ORDER BY id LIMIT ?"
        params.append(limit)
    else:
        sql = ("SELECT COUNT(*) AS order_count, COALESCE(SUM(amount_cents), 0) AS total_cents "
               f"FROM orders WHERE {where}")
    return sql, tuple(params)


def extract_unsafe_sql(raw: str) -> str:
    obj = decode_object(raw)
    if set(obj) != {"sql"} or not isinstance(obj["sql"], str) or not obj["sql"].strip():
        raise PolicyError('Vulnerable mode expects {"sql": "..."}')
    return obj["sql"]
