# modification_methods/change_recipient.py
from __future__ import annotations

from typing import Any, Dict

METHOD_ID = "change_recipient"
METHOD_NAME = "Tamper metadata: change recipient field (to)"
CONFIG_FIELDS = [
    {"key": "new_to", "label": "New recipient (to)", "type": "str", "default": "EVE"},
]


def modify(record: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(record)
    out["to"] = str(config.get("new_to", "EVE"))
    return out
