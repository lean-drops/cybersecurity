# acl_rbac_scopes_demo.py
import tkinter as tk
from tkinter import ttk
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import tkinter.font as tkfont


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
    description: str = ""       # human explanation


# ----------------------------
# Policy engine
# ----------------------------

def _match_pattern(value: str, pattern: str) -> bool:
    # Supported patterns:
    # - "*" matches everything
    # - "prefix*" matches anything starting with "prefix"
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
    acl_by_resource_pattern: Dict[str, List[AclEntry]],
    endpoint: Endpoint,
    token_scopes: Set[str],
) -> Tuple[bool, List[str]]:
    reasons: List[str] = []

    # Step 1: Scopes gate (token must include all required scopes)
    missing_scopes = sorted(list(endpoint.required_scopes - token_scopes))
    if missing_scopes:
        reasons.append("STEP 1 (Scopes): DENY")
        reasons.append("Missing required scopes: " + ", ".join(missing_scopes))
        reasons.append("Required scopes: " + (", ".join(sorted(endpoint.required_scopes)) if endpoint.required_scopes else "(none)"))
        reasons.append("Token scopes: " + (", ".join(sorted(token_scopes)) if token_scopes else "(none)"))
        return (False, reasons)
    reasons.append("STEP 1 (Scopes): OK (" + (", ".join(sorted(endpoint.required_scopes)) if endpoint.required_scopes else "none") + ")")

    # Step 2: RBAC (any role permission matches)
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
    reasons.append("STEP 2 (RBAC): " + ("OK" if rbac_allowed else "NO MATCH"))
    reasons.extend(rbac_hits if rbac_hits else ["RBAC: no matching permission"])

    # Step 3: ACL overrides (deny overrides everything; allow can grant)
    acl_candidates: List[Tuple[str, AclEntry]] = []
    for pattern_key, entries in acl_by_resource_pattern.items():
        if _match_pattern(endpoint.resource, pattern_key):
            for e in entries:
                acl_candidates.append((pattern_key, e))

    acl_deny_hits: List[str] = []
    acl_allow_hits: List[str] = []
    for _pattern_key, entry in acl_candidates:
        if _acl_matches(entry, user, user_roles, endpoint.action, endpoint.resource):
            msg = f"ACL {entry.effect} match: {entry.subject_type}:{entry.subject_id} ({entry.action}, {entry.resource})"
            if entry.effect == "deny":
                acl_deny_hits.append(msg)
            elif entry.effect == "allow":
                acl_allow_hits.append(msg)

    if acl_deny_hits:
        reasons.append("STEP 3 (ACL): DENY OVERRIDE")
        reasons.extend(acl_deny_hits)
        reasons.append("FINAL: DENY (ACL deny overrides)")
        return (False, reasons)

    if acl_allow_hits:
        reasons.append("STEP 3 (ACL): ALLOW OVERRIDE")
        reasons.extend(acl_allow_hits)
        reasons.append("FINAL: ALLOW (ACL allows, no deny matched)")
        return (True, reasons)

    reasons.append("STEP 3 (ACL): NO MATCH")

    # Final fallback to RBAC
    if rbac_allowed:
        reasons.append("FINAL: ALLOW (RBAC allowed, no ACL override)")
        return (True, reasons)

    reasons.append("FINAL: DENY (neither RBAC nor ACL allowed)")
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
    acl_by_resource_pattern: Dict[str, List[AclEntry]] = {
        "doc:public": [
            AclEntry("deny", "user", "bob", "delete", "doc:public"),
        ],
        "doc:secret": [
            AclEntry("deny", "role", "viewer", "read", "doc:secret"),
            AclEntry("deny", "role", "editor", "read", "doc:secret"),
            AclEntry("allow", "user", "alice", "read", "doc:secret"),
        ],
        "doc:*": [
            AclEntry("deny", "role", "viewer", "write", "doc:*"),
        ],
    }

    endpoints_by_id: Dict[str, Endpoint] = {
        "GET /docs/public": Endpoint(
            "GET /docs/public",
            "GET",
            "/docs/public",
            "read",
            "doc:public",
            {"docs:read"},
            "Liest oeffentliche Dokumente."
        ),
        "POST /docs/public": Endpoint(
            "POST /docs/public",
            "POST",
            "/docs/public",
            "write",
            "doc:public",
            {"docs:write"},
            "Schreibt/erstellt oeffentliche Dokumente."
        ),
        "DELETE /docs/public": Endpoint(
            "DELETE /docs/public",
            "DELETE",
            "/docs/public",
            "delete",
            "doc:public",
            {"docs:delete"},
            "Loescht oeffentliche Dokumente."
        ),
        "GET /docs/secret": Endpoint(
            "GET /docs/secret",
            "GET",
            "/docs/secret",
            "read",
            "doc:secret",
            {"docs:read", "docs:secret"},
            "Liest geheime Dokumente (zusaetzlicher Scope)."
        ),
    }

    all_scopes: Set[str] = {"docs:read", "docs:write", "docs:delete", "docs:secret"}
    return users_by_id, roles_by_id, acl_by_resource_pattern, endpoints_by_id, all_scopes


# ----------------------------
# Small UI helpers
# ----------------------------

class Tooltip:
    def __init__(self, widget: tk.Widget, text: str) -> None:
        self.widget = widget
        self.text = text
        self.tip: Optional[tk.Toplevel] = None
        self.widget.bind("<Enter>", self._on_enter)
        self.widget.bind("<Leave>", self._on_leave)

    def _on_enter(self, _event: tk.Event) -> None:
        if self.tip is not None:
            return
        x = self.widget.winfo_rootx() + 16
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        label = ttk.Label(self.tip, text=self.text, padding=8)
        label.pack()

    def _on_leave(self, _event: tk.Event) -> None:
        if self.tip is not None:
            self.tip.destroy()
            self.tip = None


class ScrollableFrame(ttk.Frame):
    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self.canvas = tk.Canvas(self, highlightthickness=0)
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = ttk.Frame(self.canvas)

        self.inner.bind("<Configure>", self._on_configure)
        self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.vsb.set)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _on_configure(self, _event: tk.Event) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_mousewheel(self, event: tk.Event) -> None:
        try:
            delta = int(-1 * (event.delta / 120))
        except Exception:
            delta = 0
        if delta != 0:
            self.canvas.yview_scroll(delta, "units")


# ----------------------------
# Tkinter GUI
# ----------------------------

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("ACL + RBAC + Scopes - Policy Simulator")
        self.geometry("1280x820")
        self.minsize(1100, 720)

        self.users_by_id, self.roles_by_id, self.acl_by_resource_pattern, self.endpoints_by_id, self.all_scopes = build_demo_data()

        self.selected_user_id = tk.StringVar(value="alice")
        self.selected_endpoint_id = tk.StringVar(value="GET /docs/public")

        self.scope_vars: Dict[str, tk.BooleanVar] = {}
        for s in sorted(self.all_scopes):
            self.scope_vars[s] = tk.BooleanVar(value=(s == "docs:read"))

        self.status_var = tk.StringVar(value="Ready.")
        self.scenario_var = tk.StringVar(value="(choose a scenario)")

        self._configure_style()
        self._build_ui()
        self._refresh_all_context()

    def _configure_style(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        default_font = tkfont.nametofont("TkDefaultFont")
        default_font.configure(size=11)
        text_font = tkfont.nametofont("TkTextFont")
        text_font.configure(size=11)
        fixed_font = tkfont.nametofont("TkFixedFont")
        fixed_font.configure(size=11)

        heading_font = tkfont.nametofont("TkHeadingFont")
        heading_font.configure(size=12, weight="bold")

        style.configure("Title.TLabel", font=("TkDefaultFont", 16, "bold"))
        style.configure("Section.TLabelframe", padding=10)
        style.configure("Section.TLabelframe.Label", font=("TkDefaultFont", 12, "bold"))
        style.configure("Big.TButton", padding=(12, 8))
        style.configure("Mono.TLabel", font=("TkFixedFont", 11))

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=12)
        root.pack(fill=tk.BOTH, expand=True)
        root.rowconfigure(1, weight=1)
        root.columnconfigure(0, weight=1)

        header = ttk.Frame(root)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)

        ttk.Label(header, text="Policy Simulator", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(header, text="Scopes -> RBAC -> ACL (deny overrides)", style="Mono.TLabel").grid(row=0, column=1, sticky="w", padx=12)

        self.notebook = ttk.Notebook(root)
        self.notebook.grid(row=1, column=0, sticky="nsew", pady=(10, 8))

        self.tab_sim = ttk.Frame(self.notebook, padding=10)
        self.tab_policies = ttk.Frame(self.notebook, padding=10)
        self.tab_concepts = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_sim, text="Simulator")
        self.notebook.add(self.tab_policies, text="Policies")
        self.notebook.add(self.tab_concepts, text="Erklaerung")

        self._build_tab_simulator()
        self._build_tab_policies()
        self._build_tab_concepts()

        status = ttk.Frame(root)
        status.grid(row=2, column=0, sticky="ew")
        status.columnconfigure(0, weight=1)
        ttk.Label(status, textvariable=self.status_var).grid(row=0, column=0, sticky="w")
        ttk.Button(status, text="Reset demo data", command=self._reset_data).grid(row=0, column=1, sticky="e", padx=(8, 0))

    def _build_tab_simulator(self) -> None:
        self.tab_sim.columnconfigure(0, weight=1)
        self.tab_sim.columnconfigure(1, weight=1)
        self.tab_sim.columnconfigure(2, weight=2)
        self.tab_sim.rowconfigure(0, weight=1)

        left = ttk.Frame(self.tab_sim)
        mid = ttk.Frame(self.tab_sim)
        right = ttk.Frame(self.tab_sim)

        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        mid.grid(row=0, column=1, sticky="nsew", padx=(0, 10))
        right.grid(row=0, column=2, sticky="nsew")

        # LEFT: Request (endpoint) selection
        lf_req = ttk.Labelframe(left, text="1) Request (Endpoint)", style="Section.TLabelframe")
        lf_req.pack(fill=tk.BOTH, expand=False, pady=(0, 10))

        self.endpoint_combo = ttk.Combobox(
            lf_req,
            textvariable=self.selected_endpoint_id,
            values=sorted(self.endpoints_by_id.keys()),
            state="readonly"
        )
        self.endpoint_combo.pack(fill=tk.X)
        self.endpoint_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_all_context())
        Tooltip(self.endpoint_combo, "Ein Endpoint ist hier: HTTP-Methode + Pfad (z.B. GET /docs/public).")

        self.endpoint_details = tk.Text(lf_req, height=9, wrap="word")
        self.endpoint_details.pack(fill=tk.BOTH, expand=True, pady=(8, 0))
        self.endpoint_details.configure(state=tk.DISABLED)

        # LEFT: Scenario quick loader
        lf_scn = ttk.Labelframe(left, text="Schnelltests (Scenario)", style="Section.TLabelframe")
        lf_scn.pack(fill=tk.X, expand=False)

        scenarios = [
            "(choose a scenario)",
            "alice reads public (allow)",
            "alice reads secret (allow via ACL exception)",
            "bob deletes public (deny: scope + RBAC no + ACL deny for bob delete)",
            "carol writes public (deny: viewer write blocked by ACL deny on viewer role)",
            "dave reads secret (allow: admin)",
            "missing scopes example (deny in step 1)",
        ]
        row = ttk.Frame(lf_scn)
        row.pack(fill=tk.X)
        self.scenario_combo = ttk.Combobox(row, textvariable=self.scenario_var, values=scenarios, state="readonly")
        self.scenario_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(row, text="Load", command=self._load_scenario).pack(side=tk.LEFT, padx=(8, 0))
        Tooltip(self.scenario_combo, "Setzt User, Endpoint und Token-Scopes auf typische Beispiele.")

        # MID: User + scopes
        lf_user = ttk.Labelframe(mid, text="2) User und Rollen (RBAC)", style="Section.TLabelframe")
        lf_user.pack(fill=tk.BOTH, expand=False, pady=(0, 10))

        self.user_combo = ttk.Combobox(
            lf_user,
            textvariable=self.selected_user_id,
            values=sorted(self.users_by_id.keys()),
            state="readonly"
        )
        self.user_combo.pack(fill=tk.X)
        self.user_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_all_context())
        Tooltip(self.user_combo, "User hat Rollen. Rollen geben Permissions: (action, resource).")

        self.roles_text = tk.Text(lf_user, height=8, wrap="word")
        self.roles_text.pack(fill=tk.BOTH, expand=True, pady=(8, 0))
        self.roles_text.configure(state=tk.DISABLED)

        lf_scopes = ttk.Labelframe(mid, text="3) Token Scopes (OAuth)", style="Section.TLabelframe")
        lf_scopes.pack(fill=tk.BOTH, expand=True)

        scope_btns = ttk.Frame(lf_scopes)
        scope_btns.pack(fill=tk.X)
        ttk.Button(scope_btns, text="Select required", command=self._select_required_scopes).pack(side=tk.LEFT)
        ttk.Button(scope_btns, text="Clear", command=self._clear_scopes).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(scope_btns, text="Select all", command=self._select_all_scopes).pack(side=tk.LEFT, padx=(8, 0))

        self.scopes_scroll = ScrollableFrame(lf_scopes)
        self.scopes_scroll.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        self.scope_checks: Dict[str, ttk.Checkbutton] = {}
        for s in sorted(self.all_scopes):
            cb = ttk.Checkbutton(self.scopes_scroll.inner, text=s, variable=self.scope_vars[s])
            cb.pack(anchor="w")
            self.scope_checks[s] = cb
            Tooltip(cb, "Scope muss im Token vorhanden sein, sonst DENY in Step 1.")

        # RIGHT: Evaluate + output + small explanation
        actions = ttk.Frame(right)
        actions.pack(fill=tk.X)

        self.btn_eval = ttk.Button(actions, text="Evaluate", style="Big.TButton", command=self._evaluate)
        self.btn_eval.pack(side=tk.LEFT)
        Tooltip(self.btn_eval, "Fuehrt den Check aus: Scopes -> RBAC -> ACL -> FINAL.")

        ttk.Button(actions, text="Clear output", command=self._clear_output).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(actions, text="Copy output", command=self._copy_output).pack(side=tk.LEFT, padx=(8, 0))

        lf_map = ttk.Labelframe(right, text="Endpoint Mapping (warum action/resource?)", style="Section.TLabelframe")
        lf_map.pack(fill=tk.X, pady=(10, 10))
        self.mapping_text = tk.Text(lf_map, height=6, wrap="word")
        self.mapping_text.pack(fill=tk.X)
        self.mapping_text.configure(state=tk.DISABLED)

        lf_out = ttk.Labelframe(right, text="Decision Output", style="Section.TLabelframe")
        lf_out.pack(fill=tk.BOTH, expand=True)
        self.output = tk.Text(lf_out, wrap="word")
        self.output.pack(fill=tk.BOTH, expand=True)
        self.output.tag_configure("ALLOW", font=("TkDefaultFont", 12, "bold"))
        self.output.tag_configure("DENY", font=("TkDefaultFont", 12, "bold"))
        self.output.tag_configure("STEP", font=("TkDefaultFont", 11, "bold"))
        self.output.tag_configure("HINT", foreground="gray")

        self._append_output("Ready.\n", tag="HINT")

    def _build_tab_policies(self) -> None:
        self.tab_policies.columnconfigure(0, weight=1)
        self.tab_policies.columnconfigure(1, weight=2)
        self.tab_policies.rowconfigure(0, weight=1)

        left = ttk.Frame(self.tab_policies)
        right = ttk.Frame(self.tab_policies)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        right.grid(row=0, column=1, sticky="nsew")

        # Roles overview
        lf_roles = ttk.Labelframe(left, text="RBAC Roles und Permissions", style="Section.TLabelframe")
        lf_roles.pack(fill=tk.BOTH, expand=True)

        self.roles_tree = ttk.Treeview(lf_roles, columns=("role", "permissions"), show="headings", height=12)
        self.roles_tree.heading("role", text="role")
        self.roles_tree.heading("permissions", text="permissions (action, resource)")
        self.roles_tree.column("role", width=120, anchor="w")
        self.roles_tree.column("permissions", width=520, anchor="w")
        self.roles_tree.pack(fill=tk.BOTH, expand=True)

        # ACL editor
        lf_acl = ttk.Labelframe(right, text="ACL (Allow/Deny pro User oder Role)", style="Section.TLabelframe")
        lf_acl.pack(fill=tk.BOTH, expand=True)

        form = ttk.Frame(lf_acl)
        form.pack(fill=tk.X)

        self.acl_effect = tk.StringVar(value="deny")
        self.acl_subject_type = tk.StringVar(value="role")
        self.acl_subject_id = tk.StringVar(value="viewer")
        self.acl_action = tk.StringVar(value="read")
        self.acl_resource = tk.StringVar(value="doc:secret")

        r0 = ttk.Frame(form)
        r0.pack(fill=tk.X, pady=2)
        ttk.Label(r0, text="effect").grid(row=0, column=0, sticky="w")
        ttk.Combobox(r0, textvariable=self.acl_effect, values=["allow", "deny"], state="readonly", width=10).grid(row=0, column=1, padx=6)
        ttk.Label(r0, text="subject_type").grid(row=0, column=2, sticky="w")
        ttk.Combobox(r0, textvariable=self.acl_subject_type, values=["user", "role"], state="readonly", width=10).grid(row=0, column=3, padx=6)

        r1 = ttk.Frame(form)
        r1.pack(fill=tk.X, pady=2)
        ttk.Label(r1, text="subject_id").grid(row=0, column=0, sticky="w")
        self.subject_id_combo = ttk.Combobox(r1, textvariable=self.acl_subject_id, values=sorted(self.roles_by_id.keys()), state="readonly")
        self.subject_id_combo.grid(row=0, column=1, padx=6, sticky="ew")
        r1.columnconfigure(1, weight=1)

        ttk.Label(r1, text="action").grid(row=0, column=2, sticky="w")
        ttk.Combobox(r1, textvariable=self.acl_action, values=["read", "write", "delete", "*"], state="readonly", width=10).grid(row=0, column=3, padx=6)

        r2 = ttk.Frame(form)
        r2.pack(fill=tk.X, pady=2)
        ttk.Label(r2, text="resource_pattern").grid(row=0, column=0, sticky="w")
        ttk.Entry(r2, textvariable=self.acl_resource, width=28).grid(row=0, column=1, padx=6, sticky="w")
        ttk.Label(r2, text="Beispiele: doc:public, doc:secret, doc:*").grid(row=0, column=2, columnspan=2, sticky="w")

        r3 = ttk.Frame(form)
        r3.pack(fill=tk.X, pady=(6, 6))
        ttk.Button(r3, text="Add ACL entry", command=self._add_acl_entry).pack(side=tk.LEFT)
        ttk.Button(r3, text="Remove selected", command=self._remove_selected_acl_entry).pack(side=tk.LEFT, padx=(8, 0))

        self.acl_subject_type.trace_add("write", lambda *_a: self._refresh_subject_id_combo())

        self.acl_tree = ttk.Treeview(lf_acl, columns=("pattern", "effect", "subject", "action", "resource"), show="headings")
        for col, w in [("pattern", 180), ("effect", 70), ("subject", 180), ("action", 80), ("resource", 180)]:
            self.acl_tree.heading(col, text=col)
            self.acl_tree.column(col, width=w, anchor="w")
        self.acl_tree.pack(fill=tk.BOTH, expand=True)

        hint = ttk.Label(lf_acl, text="Regel: ACL deny uebersteuert alles. ACL allow kann zusaetzlich erlauben.")
        hint.pack(anchor="w", pady=(6, 0))

    def _build_tab_concepts(self) -> None:
        self.tab_concepts.columnconfigure(0, weight=1)
        self.tab_concepts.rowconfigure(0, weight=1)

        lf = ttk.Labelframe(self.tab_concepts, text="Wie das Modell funktioniert", style="Section.TLabelframe")
        lf.grid(row=0, column=0, sticky="nsew")

        self.help_text = tk.Text(lf, wrap="word")
        self.help_text.pack(fill=tk.BOTH, expand=True)

        self.help_text.insert(
            "1.0",
            "Begriffe:\n"
            "\n"
            "1) Endpoint\n"
            "- In echten APIs: Methode + Pfad, z.B. GET /docs/public\n"
            "- In diesem Demo: Ein Endpoint enthaelt zusaetzlich:\n"
            "  action  (read/write/delete) und resource (z.B. doc:public)\n"
            "  required_scopes (z.B. docs:read)\n"
            "\n"
            "Warum action/resource?\n"
            "- Policies entscheiden meistens nicht ueber URL-Strings, sondern ueber 'was will ich tun' (action)\n"
            "  und 'worauf' (resource). Der Endpoint ist nur die Uebersetzung vom Web-Request in diese Begriffe.\n"
            "\n"
            "2) Scopes\n"
            "- Scopes sind Token-Rechte (OAuth-Style). Fehlt ein required_scope -> sofort DENY (Step 1).\n"
            "\n"
            "3) RBAC\n"
            "- User hat Rollen. Rollen haben Permissions (action, resource). Wenn irgendeine Rolle passt -> RBAC OK.\n"
            "\n"
            "4) ACL\n"
            "- ACL ist pro Resource (oder Pattern) eine Liste von Allow/Deny fuer User oder Role.\n"
            "- Wichtig: deny uebersteuert alles.\n"
            "\n"
            "Ablauf (wie Evaluate entscheidet):\n"
            "- Step 1: Scopes muessen passen\n"
            "- Step 2: RBAC prueft Rollen-Permissions\n"
            "- Step 3: ACL kann verbieten (deny) oder erlauben (allow)\n"
            "- Final: Wenn ACL nichts sagt, zaehlt RBAC\n"
            "\n"
            "Tip: Waehle im Simulator einen Endpoint und lies 'Endpoint Mapping' rechts.\n"
        )
        self.help_text.configure(state=tk.DISABLED)

    # ----------------------------
    # Context refresh
    # ----------------------------

    def _refresh_all_context(self) -> None:
        self._refresh_endpoint_details()
        self._refresh_roles_display()
        self._refresh_roles_table()
        self._refresh_acl_table()
        self._refresh_mapping_panel()
        self._refresh_subject_id_combo()

    def _refresh_endpoint_details(self) -> None:
        ep = self.endpoints_by_id[self.selected_endpoint_id.get()]
        detail = [
            f"Endpoint: {ep.endpoint_id}",
            f"Description: {ep.description}",
            "",
            f"method: {ep.method}",
            f"path:   {ep.path}",
            "",
            f"action:    {ep.action}",
            f"resource:  {ep.resource}",
            "required_scopes: " + (", ".join(sorted(ep.required_scopes)) if ep.required_scopes else "(none)"),
        ]
        self.endpoint_details.configure(state=tk.NORMAL)
        self.endpoint_details.delete("1.0", tk.END)
        self.endpoint_details.insert(tk.END, "\n".join(detail))
        self.endpoint_details.configure(state=tk.DISABLED)

    def _refresh_roles_display(self) -> None:
        user = self.users_by_id[self.selected_user_id.get()]
        lines: List[str] = []
        for rid in sorted(user.roles):
            role = self.roles_by_id.get(rid)
            if role:
                perms = "; ".join([f"({p.action}, {p.resource})" for p in role.permissions]) or "(no perms)"
                lines.append(f"- {rid}: {perms}")
            else:
                lines.append(f"- {rid}: (missing role)")
        if not lines:
            lines = ["(no roles)"]

        self.roles_text.configure(state=tk.NORMAL)
        self.roles_text.delete("1.0", tk.END)
        self.roles_text.insert(tk.END, "\n".join(lines))
        self.roles_text.configure(state=tk.DISABLED)

    def _refresh_roles_table(self) -> None:
        for iid in self.roles_tree.get_children():
            self.roles_tree.delete(iid)
        for rid in sorted(self.roles_by_id.keys()):
            role = self.roles_by_id[rid]
            perms = "; ".join([f"({p.action},{p.resource})" for p in role.permissions]) if role.permissions else "(none)"
            self.roles_tree.insert("", tk.END, values=(rid, perms))

    def _refresh_acl_table(self) -> None:
        for iid in self.acl_tree.get_children():
            self.acl_tree.delete(iid)

        rows: List[Tuple[str, str, str, str, str]] = []
        for pattern in sorted(self.acl_by_resource_pattern.keys()):
            for e in self.acl_by_resource_pattern[pattern]:
                rows.append((pattern, e.effect, f"{e.subject_type}:{e.subject_id}", e.action, e.resource))
        for r in rows:
            self.acl_tree.insert("", tk.END, values=r)

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

    def _refresh_mapping_panel(self) -> None:
        ep = self.endpoints_by_id[self.selected_endpoint_id.get()]
        mapping = [
            "Was kommt vom Request?",
            f"- method + path: {ep.method} {ep.path}",
            "",
            "Wie wird das zur Policy?",
            f"- action:   {ep.action}",
            f"- resource: {ep.resource}",
            "",
            "Welche Scopes werden verlangt?",
            "- required_scopes: " + (", ".join(sorted(ep.required_scopes)) if ep.required_scopes else "(none)"),
            "",
            "Merksatz:",
            "URL/Methode ist nur die Verpackung. Policies entscheiden ueber action/resource + scopes.",
        ]
        self.mapping_text.configure(state=tk.NORMAL)
        self.mapping_text.delete("1.0", tk.END)
        self.mapping_text.insert(tk.END, "\n".join(mapping))
        self.mapping_text.configure(state=tk.DISABLED)

    # ----------------------------
    # Output helpers
    # ----------------------------

    def _append_output(self, text: str, tag: Optional[str] = None) -> None:
        if tag:
            self.output.insert(tk.END, text, tag)
        else:
            self.output.insert(tk.END, text)
        self.output.see(tk.END)

    def _clear_output(self) -> None:
        self.output.delete("1.0", tk.END)
        self.status_var.set("Output cleared.")

    def _copy_output(self) -> None:
        try:
            txt = self.output.get("1.0", tk.END)
            self.clipboard_clear()
            self.clipboard_append(txt)
            self.status_var.set("Output copied to clipboard.")
        except Exception:
            self.status_var.set("Copy failed.")

    # ----------------------------
    # Scope controls
    # ----------------------------

    def _current_token_scopes(self) -> Set[str]:
        scopes: Set[str] = set()
        for s, v in self.scope_vars.items():
            if v.get():
                scopes.add(s)
        return scopes

    def _select_required_scopes(self) -> None:
        ep = self.endpoints_by_id[self.selected_endpoint_id.get()]
        for s in self.scope_vars:
            self.scope_vars[s].set(s in ep.required_scopes)
        self.status_var.set("Selected required scopes for current endpoint.")

    def _clear_scopes(self) -> None:
        for s in self.scope_vars:
            self.scope_vars[s].set(False)
        self.status_var.set("Scopes cleared.")

    def _select_all_scopes(self) -> None:
        for s in self.scope_vars:
            self.scope_vars[s].set(True)
        self.status_var.set("All scopes selected.")

    # ----------------------------
    # Scenarios
    # ----------------------------

    def _load_scenario(self) -> None:
        name = self.scenario_var.get()
        if name == "(choose a scenario)":
            self.status_var.set("No scenario selected.")
            return

        # Default reset scopes first
        for s in self.scope_vars:
            self.scope_vars[s].set(False)

        if name == "alice reads public (allow)":
            self.selected_user_id.set("alice")
            self.selected_endpoint_id.set("GET /docs/public")
            self.scope_vars["docs:read"].set(True)
        elif name == "alice reads secret (allow via ACL exception)":
            self.selected_user_id.set("alice")
            self.selected_endpoint_id.set("GET /docs/secret")
            self.scope_vars["docs:read"].set(True)
            self.scope_vars["docs:secret"].set(True)
        elif name == "bob deletes public (deny: scope + RBAC no + ACL deny for bob delete)":
            self.selected_user_id.set("bob")
            self.selected_endpoint_id.set("DELETE /docs/public")
            self.scope_vars["docs:delete"].set(True)
        elif name == "carol writes public (deny: viewer write blocked by ACL deny on viewer role)":
            self.selected_user_id.set("carol")
            self.selected_endpoint_id.set("POST /docs/public")
            self.scope_vars["docs:write"].set(True)
        elif name == "dave reads secret (allow: admin)":
            self.selected_user_id.set("dave")
            self.selected_endpoint_id.set("GET /docs/secret")
            self.scope_vars["docs:read"].set(True)
            self.scope_vars["docs:secret"].set(True)
        elif name == "missing scopes example (deny in step 1)":
            self.selected_user_id.set("dave")
            self.selected_endpoint_id.set("GET /docs/secret")
            # intentionally missing docs:secret
            self.scope_vars["docs:read"].set(True)
        else:
            self.status_var.set("Unknown scenario.")
            return

        self._refresh_all_context()
        self.status_var.set("Scenario loaded: " + name)

    # ----------------------------
    # ACL editing
    # ----------------------------

    def _add_acl_entry(self) -> None:
        effect = self.acl_effect.get().strip()
        st = self.acl_subject_type.get().strip()
        sid = self.acl_subject_id.get().strip()
        action = self.acl_action.get().strip()
        res = self.acl_resource.get().strip()

        if effect not in ("allow", "deny"):
            self.status_var.set("Invalid ACL effect.")
            return
        if st not in ("user", "role"):
            self.status_var.set("Invalid subject_type.")
            return
        if not sid or not action or not res:
            self.status_var.set("ACL fields must be non-empty.")
            return
        if st == "user" and sid not in self.users_by_id:
            self.status_var.set("Unknown user_id for ACL.")
            return
        if st == "role" and sid not in self.roles_by_id:
            self.status_var.set("Unknown role_id for ACL.")
            return

        entry = AclEntry(effect, st, sid, action, res)
        self.acl_by_resource_pattern.setdefault(res, []).append(entry)
        self._refresh_acl_table()
        self.status_var.set("ACL entry added.")

    def _remove_selected_acl_entry(self) -> None:
        sel = self.acl_tree.selection()
        if not sel:
            self.status_var.set("No ACL entry selected.")
            return

        item_id = sel[0]
        vals = self.acl_tree.item(item_id, "values")
        if len(vals) != 5:
            self.status_var.set("Selection invalid.")
            return

        pattern, effect, subject, action, resource = vals
        if ":" not in subject:
            self.status_var.set("Selection invalid.")
            return
        st, sid = subject.split(":", 1)
        st = st.strip()
        sid = sid.strip()

        entries = self.acl_by_resource_pattern.get(pattern, [])
        new_entries: List[AclEntry] = []
        removed = False
        for e in entries:
            if (not removed and e.effect == effect and e.subject_type == st and e.subject_id == sid and e.action == action and e.resource == resource):
                removed = True
                continue
            new_entries.append(e)

        if not removed:
            self.status_var.set("No matching ACL entry found to remove.")
            return

        if new_entries:
            self.acl_by_resource_pattern[pattern] = new_entries
        else:
            del self.acl_by_resource_pattern[pattern]
        self._refresh_acl_table()
        self.status_var.set("ACL entry removed.")

    # ----------------------------
    # Evaluate
    # ----------------------------

    def _evaluate(self) -> None:
        uid = self.selected_user_id.get()
        ep_id = self.selected_endpoint_id.get()

        user = self.users_by_id[uid]
        ep = self.endpoints_by_id[ep_id]
        token_scopes = self._current_token_scopes()

        allowed, reasons = evaluate_access(
            user=user,
            roles_by_id=self.roles_by_id,
            acl_by_resource_pattern=self.acl_by_resource_pattern,
            endpoint=ep,
            token_scopes=token_scopes,
        )

        self._append_output("\n" + ("=" * 72) + "\n", tag="HINT")
        headline = "DECISION: " + ("ALLOW" if allowed else "DENY") + "\n"
        self._append_output(headline, tag=("ALLOW" if allowed else "DENY"))

        self._append_output(f"Request:  {ep.method} {ep.path}\n")
        self._append_output(f"Mapping:  action={ep.action}, resource={ep.resource}\n")
        self._append_output("Scopes:   token=[" + (", ".join(sorted(token_scopes)) if token_scopes else "(none)") + "]\n")
        self._append_output("Required: [" + (", ".join(sorted(ep.required_scopes)) if ep.required_scopes else "(none)") + "]\n")
        self._append_output("User:     " + uid + " roles=[" + (", ".join(sorted(user.roles)) if user.roles else "(none)") + "]\n")
        self._append_output("-" * 72 + "\n", tag="HINT")

        for r in reasons:
            tag = "STEP" if r.startswith("STEP") or r.startswith("FINAL") else None
            self._append_output(r + "\n", tag=tag)

        self.status_var.set("Evaluated: " + ("ALLOW" if allowed else "DENY"))

    # ----------------------------
    # Reset
    # ----------------------------

    def _reset_data(self) -> None:
        self.users_by_id, self.roles_by_id, self.acl_by_resource_pattern, self.endpoints_by_id, self.all_scopes = build_demo_data()

        # Ensure scope vars cover all scopes
        existing = set(self.scope_vars.keys())
        for s in sorted(self.all_scopes):
            if s not in existing:
                self.scope_vars[s] = tk.BooleanVar(value=False)

        # Default scopes
        for s, v in self.scope_vars.items():
            v.set(s == "docs:read")

        self.selected_user_id.set("alice")
        self.selected_endpoint_id.set("GET /docs/public")
        self.scenario_var.set("(choose a scenario)")

        self.acl_effect.set("deny")
        self.acl_subject_type.set("role")
        self.acl_subject_id.set("viewer")
        self.acl_action.set("read")
        self.acl_resource.set("doc:secret")

        self._refresh_all_context()
        self._append_output("\nReset demo data.\n", tag="HINT")
        self.status_var.set("Demo data reset.")


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()