#!/usr/bin/env python3
"""Introspect ScheduledActionApprovePayload and approve pending actions."""

import sys
import os
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.tanium import TaniumClient

client = TaniumClient(instance="cloud")
instance = client.instances[0]

# Introspect ScheduledActionApprovePayload
INTROSPECT = """
{
  __type(name: "ScheduledActionApprovePayload") {
    fields { name type { name kind ofType { name kind } } }
  }
}
"""
r = instance.query(INTROSPECT)
fields = r.get("data", {}).get("__type", {}).get("fields", [])
print(f"ScheduledActionApprovePayload fields: {[f['name'] for f in fields]}\n")

# Build the approve mutation with correct fields
field_selections = "\n        ".join(f['name'] for f in fields[:5])  # Use first 5 fields

APPROVE_MUTATION = f"""
mutation approveAction($ref: IdRefInput!) {{
  scheduledActionApprove(ref: $ref) {{
    {field_selections}
  }}
}}
"""

print(f"Approve mutation:\n{APPROVE_MUTATION}\n")

# Approve scheduledAction 226546 (linked to action 1841033)
print("=== Approving scheduledAction 226546 ===\n")
try:
    result = instance.query(APPROVE_MUTATION, {"ref": {"id": "226546"}})
    print(json.dumps(result.get("data", {}), indent=2))
except Exception as e:
    print(f"Error: {e}")
