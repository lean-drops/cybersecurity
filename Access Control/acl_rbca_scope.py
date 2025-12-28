# acl_rbac_scopes_demo.py
import tkinter as tk
from tkinter import ttk
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# ----------------------------
# Data model
# ----------------------------

@dataclass(frozen=True)
class Permission:
    action: str                 # e.g. "read", "write", "delete", "*"
    resource: str               # e.g. "doc:public", "doc:*", "*"


@dataclass
class Role:
    role_id: str
    permissions: List[Permission] = field(default_factory=list)


@dataclass
class User:
    user_id: str
    roles: Set[str] = field(default_factory=set)


@dataclass(frozen=True)
class AclEntry:
    effect: str                 # "allow" or "deny"
    subject_type: str           # "user" or "role"
    subject_id: str             # user_id or role_id
    action: str                 # action or "*"
    resource: str               # resource or patterns like "doc:*"


@dataclass
class Endpoint:
    endpoint_id: str            # label/id
    method: str                 # GET/POST/DELETE
    path: str                   # /docs/public
    action: str                 # "read"/"write"/"delete"
    resource: str               # "doc:public"
    required_scopes: Set[str]   # e.g. {"docs:read"}


# ----------------------------
# Policy engine
# ----------------------------

def _match_pattern(value: str, pattern: str) -> bool:
    # Very small matcher: exact or prefix-star. Examples:
    # pattern "*" matches everything
    # pattern "doc:*" matches "doc:public" etc
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return value == pattern


def _permission_matches(perm: Permission, action: str, resource: str) -> bool:
    return _match_pattern(action, perm.action) and _match_pattern(resource, perm.resource)


def _acl_matches(entry: AclEntry, user: User, user_roles: Set[str], action: str, resource: str) -> bool:
    if not (_match_pattern(action, entry.action) and _match_pattern(resource, entry.resource)):
        return False
    if entry.subject_type == "user":
        return entry.subject_id == user.user_id
    if entry.subject_type == "role":
        return entry.subject_id in user_roles
    return False


def evaluate_access(
    user: User,
    roles_by_id: Dict[str, Role],
    acl_by_resource: Dict[str, List[AclEntry]],
    endpoint: Endpoint,
    token_scopes: Set[str],
) -> Tuple[bool, List[str]]:
    reasons: List[str] = []

    # 1) Scopes gate (token must include all required scopes)
    missing_scopes = sorted(list(endpoint.required_scopes - token_scopes))
    if missing_scopes:
        reasons.append("DENY: Missing required scopes: " + ", ".join(missing_scopes))
        reasons.append("Required scopes: " + ", ".join(sorted(endpoint.required_scopes)) if endpoint.required_scopes else "Required scopes: (none)")
        reasons.append("Token scopes: " + ", ".join(sorted(token_scopes)) if token_scopes else "Token scopes: (none)")
        return (False, reasons)
    reasons.append("OK: Scopes satisfied: " + (", ".join(sorted(endpoint.required_scopes)) if endpoint.required_scopes else "(none)"))

    # 2) RBAC check (any role permission matches)
    user_roles = set(user.roles)
    rbac_hits: List[str] = []
    for rid in sorted(user_roles):
        role = roles_by_id.get(rid)
        if not role:
            continue
        for perm in role.permissions:
            if _permission_matches(perm, endpoint.action, endpoint.resource):
                rbac_hits.append(f"RBAC allow via role '{rid}': ({perm.action}, {perm.resource})")
    rbac_allowed = len(rbac_hits) > 0
    if rbac_allowed:
        reasons.extend(rbac_hits)
    else:
        reasons.append("RBAC: no matching permission for action/resource")

    # 3) ACL overrides (deny overrides everything; allow can grant even if RBAC denied)
    # We apply ACL entries associated with this exact resource and also wildcard "resource groups"
    # For demo: we store ACL keyed by resource exact and by prefix patterns like "doc:*"
    acl_candidates: List[AclEntry] = []
    for key, entries in acl_by_resource.items():
        if _match_pattern(endpoint.resource, key):
            acl_candidates.extend(entries)

    acl_deny_hits: List[str] = []
    acl_allow_hits: List[str] = []
    for entry in acl_candidates:
        if _acl_matches(entry, user, user_roles, endpoint.action, endpoint.resource):
            if entry.effect == "deny":
                acl_deny_hits.append(
                    f"ACL deny match: {entry.subject_type}:{entry.subject_id} ({entry.action}, {entry.resource})"
                )
            elif entry.effect == "allow":
                acl_allow_hits.append(
                    f"ACL allow match: {entry.subject_type}:{entry.subject_id} ({entry.action}, {entry.resource})"
                )

    if acl_deny_hits:
        reasons.extend(acl_deny_hits)
        reasons.append("DENY: ACL deny overrides")
        return (False, reasons)

    if acl_allow_hits:
        reasons.extend(acl_allow_hits)
        reasons.append("ALLOW: ACL allows (and no ACL deny matched)")
        return (True, reasons)

    # If no ACL allow/deny matched, fall back to RBAC
    if rbac_allowed:
        reasons.append("ALLOW: RBAC allowed (no ACL override)")
        return (True, reasons)

    reasons.append("DENY: Neither RBAC nor ACL allowed")
    return (False, reasons)


# ----------------------------
# Demo data
# ----------------------------

def build_demo_data() -> Tuple[Dict[str, User], Dict[str, Role], Dict[str, List[AclEntry]], Dict[str, Endpoint], Set[str]]:
    roles_by_id: Dict[str, Role] = {
        "viewer": Role("viewer", [
            Permission("read", "doc:*"),
        ]),
        "editor": Role("editor", [
            Permission("read", "doc:*"),
            Permission("write", "doc:*"),
        ]),
        "admin": Role("admin", [
            Permission("*", "*"),
        ]),
    }

    users_by_id: Dict[str, User] = {
        "alice": User("alice", {"viewer"}),
        "bob": User("bob", {"editor"}),
        "carol": User("carol", {"viewer", "editor"}),
        "dave": User("dave", {"admin"}),
    }

    # ACL store: key is a resource pattern (exact or "doc:*")
    acl_by_resource: Dict[str, List[AclEntry]] = {
        "doc:public": [
            # Example: deny Bob from deleting public docs (even if his role allowed delete - it doesn't, but demo)
            AclEntry("deny", "user", "bob", "delete", "doc:public"),
        ],
        "doc:secret": [
            # Example: only admin can read secret docs by default (RBAC viewer/editor can read doc:*),
            # so we deny viewer/editor, allow admin or allow specific user
            AclEntry("deny", "role", "viewer", "read", "doc:secret"),
            AclEntry("deny", "role", "editor", "read", "doc:secret"),
            AclEntry("allow", "user", "alice", "read", "doc:secret"),  # Alice gets exception
        ],
        "doc:*": [
            # Example: deny everyone in viewer role from write on any doc (restrict)
            AclEntry("deny", "role", "viewer", "write", "doc:*"),
        ],
    }

    endpoints_by_id: Dict[str, Endpoint] = {
        "GET /docs/public": Endpoint(
            "GET /docs/public", "GET", "/docs/public", "read", "doc:public", {"docs:read"}
        ),
        "POST /docs/public": Endpoint(
            "POST /docs/public", "POST", "/docs/public", "write", "doc:public", {"docs:write"}
        ),
        "DELETE /docs/public": Endpoint(
            "DELETE /docs/public", "DELETE", "/docs/public", "delete", "doc:public", {"docs:delete"}
        ),
        "GET /docs/secret": Endpoint(
            "GET /docs/secret", "GET", "/docs/secret", "read", "doc:secret", {"docs:read", "docs:secret"}
        ),
    }

    # Universe of scopes for UI
    all_scopes: Set[str] = {"docs:read", "docs:write", "docs:delete", "docs:secret"}
    return users_by_id, roles_by_id, acl_by_resource, endpoints_by_id, all_scopes


# ----------------------------
# Tkinter GUI
# ----------------------------

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("ACL + RBAC + Scopes Demo")
        self.geometry("1100x700")

        self.users_by_id, self.roles_by_id, self.acl_by_resource, self.endpoints_by_id, self.all_scopes = build_demo_data()

        self.selected_user_id = tk.StringVar(value="alice")
        self.selected_endpoint_id = tk.StringVar(value="GET /docs/public")

        # Token scopes selection
        self.scope_vars: Dict[str, tk.BooleanVar] = {}
        for s in sorted(self.all_scopes):
            self.scope_vars[s] = tk.BooleanVar(value=(s == "docs:read"))

        self._build_ui()
        self._refresh_roles_display()
        self._refresh_acl_table()

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=10)
        root.pack(fill=tk.BOTH, expand=True)

        root.columnconfigure(0, weight=1)
        root.columnconfigure(1, weight=1)
        root.columnconfigure(2, weight=2)
        root.rowconfigure(0, weight=1)

        left = ttk.Frame(root, padding=10)
        mid = ttk.Frame(root, padding=10)
        right = ttk.Frame(root, padding=10)

        left.grid(row=0, column=0, sticky="nsew")
        mid.grid(row=0, column=1, sticky="nsew")
        right.grid(row=0, column=2, sticky="nsew")

        # LEFT: User + roles + token scopes
        ttk.Label(left, text="User").pack(anchor="w")
        user_combo = ttk.Combobox(left, textvariable=self.selected_user_id, values=sorted(self.users_by_id.keys()), state="readonly")
        user_combo.pack(fill=tk.X, pady=(0, 8))
        user_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_user_changed())

        ttk.Label(left, text="User roles (RBAC)").pack(anchor="w")
        self.roles_list = tk.Text(left, height=5, width=30)
        self.roles_list.pack(fill=tk.X, pady=(0, 8))
        self.roles_list.configure(state=tk.DISABLED)

        ttk.Label(left, text="Token scopes (OAuth-style)").pack(anchor="w")
        scopes_box = ttk.Frame(left)
        scopes_box.pack(fill=tk.X, pady=(0, 8))

        for s in sorted(self.all_scopes):
            cb = ttk.Checkbutton(scopes_box, text=s, variable=self.scope_vars[s])
            cb.pack(anchor="w")

        ttk.Separator(left).pack(fill=tk.X, pady=8)

        ttk.Label(left, text="RBAC role assignment").pack(anchor="w")
        assign_frame = ttk.Frame(left)
        assign_frame.pack(fill=tk.X, pady=(0, 6))

        self.role_to_assign = tk.StringVar(value="viewer")
        role_combo = ttk.Combobox(assign_frame, textvariable=self.role_to_assign, values=sorted(self.roles_by_id.keys()), state="readonly")
        role_combo.grid(row=0, column=0, sticky="ew")
        assign_frame.columnconfigure(0, weight=1)

        ttk.Button(assign_frame, text="Add role", command=self._add_role_to_user).grid(row=0, column=1, padx=6)
        ttk.Button(assign_frame, text="Remove role", command=self._remove_role_from_user).grid(row=0, column=2)

        # MID: Endpoint selection + ACL editor + ACL table
        ttk.Label(mid, text="Endpoint").pack(anchor="w")
        ep_combo = ttk.Combobox(mid, textvariable=self.selected_endpoint_id, values=sorted(self.endpoints_by_id.keys()), state="readonly")
        ep_combo.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(mid, text="Endpoint details").pack(anchor="w")
        self.endpoint_details = tk.Text(mid, height=6, width=40)
        self.endpoint_details.pack(fill=tk.BOTH, expand=False, pady=(0, 8))
        self.endpoint_details.configure(state=tk.DISABLED)
        ep_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_endpoint_details())
        self._refresh_endpoint_details()

        ttk.Separator(mid).pack(fill=tk.X, pady=8)

        ttk.Label(mid, text="Add ACL entry (per resource pattern)").pack(anchor="w")
        acl_form = ttk.Frame(mid)
        acl_form.pack(fill=tk.X, pady=(0, 8))

        self.acl_effect = tk.StringVar(value="deny")
        self.acl_subject_type = tk.StringVar(value="role")
        self.acl_subject_id = tk.StringVar(value="viewer")
        self.acl_action = tk.StringVar(value="read")
        self.acl_resource = tk.StringVar(value="doc:secret")  # can be "doc:*"

        row0 = ttk.Frame(acl_form)
        row0.pack(fill=tk.X, pady=2)
        ttk.Label(row0, text="effect").grid(row=0, column=0, sticky="w")
        ttk.Combobox(row0, textvariable=self.acl_effect, values=["allow", "deny"], state="readonly", width=10).grid(row=0, column=1, padx=6)
        ttk.Label(row0, text="subject_type").grid(row=0, column=2, sticky="w")
        ttk.Combobox(row0, textvariable=self.acl_subject_type, values=["user", "role"], state="readonly", width=10).grid(row=0, column=3, padx=6)

        row1 = ttk.Frame(acl_form)
        row1.pack(fill=tk.X, pady=2)
        ttk.Label(row1, text="subject_id").grid(row=0, column=0, sticky="w")
        self.subject_id_combo = ttk.Combobox(row1, textvariable=self.acl_subject_id, values=sorted(self.roles_by_id.keys()), state="readonly")
        self.subject_id_combo.grid(row=0, column=1, padx=6, sticky="ew")
        row1.columnconfigure(1, weight=1)
        self.acl_subject_type.trace_add("write", lambda *_a: self._refresh_subject_id_combo())

        row2 = ttk.Frame(acl_form)
        row2.pack(fill=tk.X, pady=2)
        ttk.Label(row2, text="action").grid(row=0, column=0, sticky="w")
        ttk.Entry(row2, textvariable=self.acl_action, width=14).grid(row=0, column=1, padx=6, sticky="w")
        ttk.Label(row2, text="resource_pattern").grid(row=0, column=2, sticky="w")
        ttk.Entry(row2, textvariable=self.acl_resource, width=16).grid(row=0, column=3, padx=6, sticky="w")

        row3 = ttk.Frame(acl_form)
        row3.pack(fill=tk.X, pady=2)
        ttk.Button(row3, text="Add ACL entry", command=self._add_acl_entry).pack(side=tk.LEFT)
        ttk.Button(row3, text="Remove selected ACL entry", command=self._remove_selected_acl_entry).pack(side=tk.LEFT, padx=6)

        ttk.Label(mid, text="ACL entries (deny overrides allow)").pack(anchor="w")
        self.acl_tree = ttk.Treeview(mid, columns=("key", "effect", "subject", "action", "resource"), show="headings", height=10)
        for col, w in [("key", 120), ("effect", 60), ("subject", 160), ("action", 80), ("resource", 160)]:
            self.acl_tree.heading(col, text=col)
            self.acl_tree.column(col, width=w, anchor="w")
        self.acl_tree.pack(fill=tk.BOTH, expand=True)

        # RIGHT: Evaluate + output
        actions = ttk.Frame(right)
        actions.pack(fill=tk.X)

        ttk.Button(actions, text="Evaluate", command=self._evaluate).pack(side=tk.LEFT)
        ttk.Button(actions, text="Reset demo data", command=self._reset_data).pack(side=tk.LEFT, padx=6)
        ttk.Button(actions, text="Clear output", command=self._clear_output).pack(side=tk.LEFT)

        ttk.Label(right, text="Decision output").pack(anchor="w", pady=(10, 0))
        self.output = tk.Text(right, wrap="word")
        self.output.pack(fill=tk.BOTH, expand=True)
        self._write_output("Ready.\n")

    def _write_output(self, text: str) -> None:
        self.output.insert(tk.END, text)
        self.output.see(tk.END)

    def _clear_output(self) -> None:
        self.output.delete("1.0", tk.END)

    def _on_user_changed(self) -> None:
        self._refresh_roles_display()

    def _refresh_roles_display(self) -> None:
        user = self.users_by_id[self.selected_user_id.get()]
        lines = []
        for rid in sorted(user.roles):
            role = self.roles_by_id.get(rid)
            if role:
                perms = "; ".join([f"({p.action},{p.resource})" for p in role.permissions]) or "(no perms)"
                lines.append(f"- {rid}: {perms}")
            else:
                lines.append(f"- {rid}: (missing role)")
        if not lines:
            lines = ["(no roles)"]

        self.roles_list.configure(state=tk.NORMAL)
        self.roles_list.delete("1.0", tk.END)
        self.roles_list.insert(tk.END, "\n".join(lines))
        self.roles_list.configure(state=tk.DISABLED)

    def _refresh_subject_id_combo(self) -> None:
        st = self.acl_subject_type.get()
        if st == "user":
            self.subject_id_combo.configure(values=sorted(self.users_by_id.keys()))
            if self.acl_subject_id.get() not in self.users_by_id:
                self.acl_subject_id.set(sorted(self.users_by_id.keys())[0])
        else:
            self.subject_id_combo.configure(values=sorted(self.roles_by_id.keys()))
            if self.acl_subject_id.get() not in self.roles_by_id:
                self.acl_subject_id.set(sorted(self.roles_by_id.keys())[0])

    def _refresh_endpoint_details(self) -> None:
        ep = self.endpoints_by_id[self.selected_endpoint_id.get()]
        detail = [
            f"endpoint_id: {ep.endpoint_id}",
            f"method:      {ep.method}",
            f"path:        {ep.path}",
            f"action:      {ep.action}",
            f"resource:    {ep.resource}",
            "required_scopes: " + (", ".join(sorted(ep.required_scopes)) if ep.required_scopes else "(none)"),
        ]
        self.endpoint_details.configure(state=tk.NORMAL)
        self.endpoint_details.delete("1.0", tk.END)
        self.endpoint_details.insert(tk.END, "\n".join(detail))
        self.endpoint_details.configure(state=tk.DISABLED)

    def _add_role_to_user(self) -> None:
        uid = self.selected_user_id.get()
        rid = self.role_to_assign.get()
        if rid in self.roles_by_id:
            self.users_by_id[uid].roles.add(rid)
            self._refresh_roles_display()

    def _remove_role_from_user(self) -> None:
        uid = self.selected_user_id.get()
        rid = self.role_to_assign.get()
        if rid in self.users_by_id[uid].roles:
            self.users_by_id[uid].roles.remove(rid)
            self._refresh_roles_display()

    def _add_acl_entry(self) -> None:
        effect = self.acl_effect.get().strip()
        st = self.acl_subject_type.get().strip()
        sid = self.acl_subject_id.get().strip()
        action = self.acl_action.get().strip()
        res = self.acl_resource.get().strip()

        if effect not in ("allow", "deny"):
            self._write_output("Invalid ACL effect (use allow/deny).\n")
            return
        if st not in ("user", "role"):
            self._write_output("Invalid subject_type (use user/role).\n")
            return
        if not sid or not action or not res:
            self._write_output("ACL fields must be non-empty.\n")
            return
        if st == "user" and sid not in self.users_by_id:
            self._write_output("Unknown user_id for ACL.\n")
            return
        if st == "role" and sid not in self.roles_by_id:
            self._write_output("Unknown role_id for ACL.\n")
            return

        entry = AclEntry(effect, st, sid, action, res)

        # Store under key = res (pattern key). We treat keys as patterns in evaluation.
        self.acl_by_resource.setdefault(res, []).append(entry)
        self._refresh_acl_table()

    def _remove_selected_acl_entry(self) -> None:
        sel = self.acl_tree.selection()
        if not sel:
            return
        item_id = sel[0]
        vals = self.acl_tree.item(item_id, "values")
        if len(vals) != 5:
            return
        key, effect, subject, action, resource = vals
        # subject is "type:id"
        if ":" not in subject:
            return
        st, sid = subject.split(":", 1)
        st = st.strip()
        sid = sid.strip()

        entries = self.acl_by_resource.get(key, [])
        new_entries: List[AclEntry] = []
        removed = False
        for e in entries:
            if (not removed and e.effect == effect and e.subject_type == st and e.subject_id == sid and e.action == action and e.resource == resource):
                removed = True
                continue
            new_entries.append(e)
        if removed:
            if new_entries:
                self.acl_by_resource[key] = new_entries
            else:
                del self.acl_by_resource[key]
            self._refresh_acl_table()

    def _refresh_acl_table(self) -> None:
        for iid in self.acl_tree.get_children():
            self.acl_tree.delete(iid)

        rows: List[Tuple[str, str, str, str, str]] = []
        for key in sorted(self.acl_by_resource.keys()):
            for e in self.acl_by_resource[key]:
                rows.append((key, e.effect, f"{e.subject_type}:{e.subject_id}", e.action, e.resource))

        for r in rows:
            self.acl_tree.insert("", tk.END, values=r)

    def _current_token_scopes(self) -> Set[str]:
        scopes: Set[str] = set()
        for s, v in self.scope_vars.items():
            if v.get():
                scopes.add(s)
        return scopes

    def _evaluate(self) -> None:
        uid = self.selected_user_id.get()
        ep_id = self.selected_endpoint_id.get()
        user = self.users_by_id[uid]
        endpoint = self.endpoints_by_id[ep_id]
        token_scopes = self._current_token_scopes()

        allowed, reasons = evaluate_access(
            user=user,
            roles_by_id=self.roles_by_id,
            acl_by_resource=self.acl_by_resource,
            endpoint=endpoint,
            token_scopes=token_scopes,
        )

        self._write_output("\n---\n")
        self._write_output(f"User: {uid}\n")
        self._write_output("Roles: " + (", ".join(sorted(user.roles)) if user.roles else "(none)") + "\n")
        self._write_output(f"Endpoint: {endpoint.endpoint_id} ({endpoint.action} {endpoint.resource})\n")
        self._write_output("Token scopes: " + (", ".join(sorted(token_scopes)) if token_scopes else "(none)") + "\n")
        self._write_output("Decision: " + ("ALLOW" if allowed else "DENY") + "\n")
        self._write_output("Reasons:\n")
        for r in reasons:
            self._write_output(" - " + r + "\n")

    def _reset_data(self) -> None:
        self.users_by_id, self.roles_by_id, self.acl_by_resource, self.endpoints_by_id, self.all_scopes = build_demo_data()

        # refresh scope vars to include all scopes again
        existing = set(self.scope_vars.keys())
        for s in sorted(self.all_scopes):
            if s not in existing:
                self.scope_vars[s] = tk.BooleanVar(value=False)

        # default scopes
        for s, v in self.scope_vars.items():
            v.set(s == "docs:read")

        # refresh combos
        self.selected_user_id.set("alice")
        self.selected_endpoint_id.set("GET /docs/public")
        self.role_to_assign.set("viewer")
        self.acl_subject_type.set("role")
        self.acl_subject_id.set("viewer")
        self.acl_effect.set("deny")
        self.acl_action.set("read")
        self.acl_resource.set("doc:secret")

        self._refresh_subject_id_combo()
        self._refresh_roles_display()
        self._refresh_endpoint_details()
        self._refresh_acl_table()
        self._write_output("\n---\nReset demo data.\n")


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()