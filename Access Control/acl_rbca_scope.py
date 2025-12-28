# pyside_policy_simulator.py
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

try:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import (
        QApplication,
        QComboBox,
        QFormLayout,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QPlainTextEdit,
        QSplitter,
        QTabWidget,
        QTableWidget,
        QTableWidgetItem,
        QTextEdit,
        QTreeWidget,
        QTreeWidgetItem,
        QVBoxLayout,
        QWidget,
    )
except Exception as e:
    raise SystemExit(
        "PySide6 is required to run this program.\n"
        "Install: pip install PySide6\n"
        f"Import error: {e}"
    )


# ----------------------------
# Data model
# ----------------------------

@dataclass(frozen=True)
class Permission:
    action: str
    resource: str


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
    effect: str        # "allow" or "deny"
    subject_type: str  # "user" or "role"
    subject_id: str
    action: str
    resource: str


@dataclass
class Endpoint:
    endpoint_id: str
    method: str
    path: str
    action: str
    resource: str
    required_scopes: Set[str]
    description: str = ""


# ----------------------------
# Policy engine
# ----------------------------

def match_pattern(value: str, pattern: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return value == pattern


def permission_matches(perm: Permission, action: str, resource: str) -> bool:
    return match_pattern(action, perm.action) and match_pattern(resource, perm.resource)


def acl_matches(entry: AclEntry, user: User, user_roles: Set[str], action: str, resource: str) -> bool:
    if not (match_pattern(action, entry.action) and match_pattern(resource, entry.resource)):
        return False
    if entry.subject_type == "user":
        return entry.subject_id == user.user_id
    if entry.subject_type == "role":
        return entry.subject_id in user_roles
    return False


Step = Tuple[str, str, List[str]]  # (title, status, lines)


def evaluate_access(
    user: User,
    roles_by_id: Dict[str, Role],
    acl_by_resource_pattern: Dict[str, List[AclEntry]],
    endpoint: Endpoint,
    token_scopes: Set[str],
) -> Tuple[bool, List[Step]]:
    steps: List[Step] = []

    missing = sorted(list(endpoint.required_scopes - token_scopes))
    if missing:
        steps.append((
            "Step 1: Scopes (token gate)",
            "DENY",
            [
                "Missing required scopes: " + ", ".join(missing),
                "Required scopes: " + (", ".join(sorted(endpoint.required_scopes)) if endpoint.required_scopes else "(none)"),
                "Token scopes: " + (", ".join(sorted(token_scopes)) if token_scopes else "(none)"),
            ],
        ))
        steps.append(("Final", "DENY", ["Reason: token does not have the required scopes."]))
        return (False, steps)

    steps.append((
        "Step 1: Scopes (token gate)",
        "OK",
        [
            "Required scopes satisfied: " + (", ".join(sorted(endpoint.required_scopes)) if endpoint.required_scopes else "(none)"),
        ],
    ))

    user_roles = set(user.roles)
    rbac_hits: List[str] = []
    for rid in sorted(user_roles):
        role = roles_by_id.get(rid)
        if not role:
            continue
        for perm in role.permissions:
            if permission_matches(perm, endpoint.action, endpoint.resource):
                rbac_hits.append(f"Allow via role '{rid}': ({perm.action}, {perm.resource})")

    rbac_ok = len(rbac_hits) > 0
    steps.append((
        "Step 2: RBAC (roles -> permissions)",
        "OK" if rbac_ok else "NO MATCH",
        rbac_hits if rbac_hits else ["No role permission matched (action, resource)."],
    ))

    acl_candidates: List[AclEntry] = []
    for pattern_key, entries in acl_by_resource_pattern.items():
        if match_pattern(endpoint.resource, pattern_key):
            acl_candidates.extend(entries)

    deny_hits: List[str] = []
    allow_hits: List[str] = []
    for entry in acl_candidates:
        if acl_matches(entry, user, user_roles, endpoint.action, endpoint.resource):
            line = f"{entry.effect.upper()} match: {entry.subject_type}:{entry.subject_id} ({entry.action}, {entry.resource})"
            if entry.effect == "deny":
                deny_hits.append(line)
            else:
                allow_hits.append(line)

    if deny_hits:
        steps.append(("Step 3: ACL (object exceptions)", "DENY OVERRIDE", deny_hits))
        steps.append(("Final", "DENY", ["Reason: ACL deny overrides everything."]))
        return (False, steps)

    if allow_hits:
        steps.append(("Step 3: ACL (object exceptions)", "ALLOW OVERRIDE", allow_hits))
        steps.append(("Final", "ALLOW", ["Reason: ACL allow grants access (no deny matched)."]))
        return (True, steps)

    steps.append(("Step 3: ACL (object exceptions)", "NO MATCH", ["No ACL entry matched."]))

    if rbac_ok:
        steps.append(("Final", "ALLOW", ["Reason: RBAC allowed and ACL did not override."]))
        return (True, steps)

    steps.append(("Final", "DENY", ["Reason: neither RBAC nor ACL allowed."]))
    return (False, steps)


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
            "Read public documents.",
        ),
        "POST /docs/public": Endpoint(
            "POST /docs/public",
            "POST",
            "/docs/public",
            "write",
            "doc:public",
            {"docs:write"},
            "Create or update public documents.",
        ),
        "DELETE /docs/public": Endpoint(
            "DELETE /docs/public",
            "DELETE",
            "/docs/public",
            "delete",
            "doc:public",
            {"docs:delete"},
            "Delete public documents.",
        ),
        "GET /docs/secret": Endpoint(
            "GET /docs/secret",
            "GET",
            "/docs/secret",
            "read",
            "doc:secret",
            {"docs:read", "docs:secret"},
            "Read secret documents (extra scope required).",
        ),
    }

    all_scopes: Set[str] = {"docs:read", "docs:write", "docs:delete", "docs:secret"}
    return users_by_id, roles_by_id, acl_by_resource_pattern, endpoints_by_id, all_scopes


# ----------------------------
# GUI
# ----------------------------

class MainWindow(QMainWindow):
    def __init__(self, app: QApplication) -> None:
        super().__init__()
        self._app = app

        self.users_by_id, self.roles_by_id, self.acl_by_resource_pattern, self.endpoints_by_id, self.all_scopes = build_demo_data()

        self.setWindowTitle("ACL + RBAC + Scopes - Policy Simulator (PySide)")
        self._apply_auto_font()
        self._build_ui()
        self._load_qss()
        self._apply_auto_window_sizing()
        self._refresh_all()

    def _apply_auto_font(self) -> None:
        screen = self._app.primaryScreen()
        if not screen:
            return
        h = max(600, screen.availableGeometry().height())

        # conservative scaling for laptops (avoid oversizing)
        if h <= 768:
            pt = 10
        elif h <= 900:
            pt = 11
        else:
            pt = 12

        f = self._app.font()
        if isinstance(f, QFont):
            f.setPointSize(pt)
            self._app.setFont(f)

    def _apply_auto_window_sizing(self) -> None:
        screen = self._app.primaryScreen()
        if not screen:
            self.resize(1100, 720)
            return

        g = screen.availableGeometry()
        sw, sh = g.width(), g.height()

        # Fit inside available area with margin; never exceed.
        target_w = int(sw * 0.92)
        target_h = int(sh * 0.88)

        # Guard rails for tiny displays.
        target_w = max(900, min(target_w, sw - 20))
        target_h = max(620, min(target_h, sh - 20))

        self.resize(target_w, target_h)

        x = g.x() + max(0, (sw - target_w) // 2)
        y = g.y() + max(0, (sh - target_h) // 2)
        self.move(x, y)

        # Keep minimum size reasonable (must not push off-screen).
        self.setMinimumSize(min(900, sw - 40), min(620, sh - 40))

        # Set initial splitter sizes based on current window width.
        total = max(900, self.width())
        left = int(total * 0.44)
        right = total - left
        self.sim_splitter.setSizes([left, right])

        total2 = max(900, self.width())
        left2 = int(total2 * 0.40)
        right2 = total2 - left2
        self.pol_splitter.setSizes([left2, right2])

    def _load_qss(self) -> None:
        qss_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "style.qss")
        if os.path.exists(qss_path):
            try:
                with open(qss_path, "r", encoding="utf-8") as f:
                    self.setStyleSheet(f.read())
            except Exception:
                pass

    def _build_ui(self) -> None:
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.tab_sim = QWidget()
        self.tab_policies = QWidget()
        self.tab_help = QWidget()

        self.tabs.addTab(self.tab_sim, "Simulator")
        self.tabs.addTab(self.tab_policies, "Policies")
        self.tabs.addTab(self.tab_help, "Explanation")

        self._build_tab_sim()
        self._build_tab_policies()
        self._build_tab_help()

    # -------- Tab: Simulator --------

    def _build_tab_sim(self) -> None:
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        self.tab_sim.setLayout(layout)

        self.sim_splitter = QSplitter(Qt.Horizontal)
        self.sim_splitter.setChildrenCollapsible(False)
        layout.addWidget(self.sim_splitter)

        # LEFT: selection
        left = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)
        left.setLayout(left_layout)

        gb_scn = QGroupBox("Quick scenarios")
        h = QHBoxLayout()
        h.setSpacing(8)
        gb_scn.setLayout(h)

        self.scenario_combo = QComboBox()
        self.scenario_combo.addItems([
            "(choose)",
            "alice reads public (allow)",
            "alice reads secret (allow via ACL exception)",
            "bob deletes public (deny via ACL deny)",
            "carol writes public (deny via missing scope unless selected)",
            "dave reads secret (allow: admin + scopes)",
            "missing scopes example (deny in step 1)",
        ])
        h.addWidget(self.scenario_combo, 1)

        self.btn_load_scn = QPushButton("Load")
        self.btn_load_scn.clicked.connect(self._load_scenario)
        h.addWidget(self.btn_load_scn)

        left_layout.addWidget(gb_scn)

        gb_req = QGroupBox("1) Request preset (Endpoint)")
        v = QVBoxLayout()
        v.setSpacing(8)
        gb_req.setLayout(v)

        self.endpoint_combo = QComboBox()
        self.endpoint_combo.addItems(sorted(self.endpoints_by_id.keys()))
        self.endpoint_combo.currentTextChanged.connect(lambda _t: self._refresh_all())
        v.addWidget(self.endpoint_combo)

        self.endpoint_tabs = QTabWidget()

        self.endpoint_details = QTextEdit()
        self.endpoint_details.setReadOnly(True)
        self.endpoint_details.setMinimumHeight(140)

        self.mapping_box = QTextEdit()
        self.mapping_box.setReadOnly(True)
        self.mapping_box.setMinimumHeight(140)

        self.endpoint_tabs.addTab(self.endpoint_details, "Details")
        self.endpoint_tabs.addTab(self.mapping_box, "Mapping")
        v.addWidget(self.endpoint_tabs)

        left_layout.addWidget(gb_req)

        gb_user = QGroupBox("2) User and roles (RBAC)")
        v = QVBoxLayout()
        v.setSpacing(8)
        gb_user.setLayout(v)

        self.user_combo = QComboBox()
        self.user_combo.addItems(sorted(self.users_by_id.keys()))
        self.user_combo.currentTextChanged.connect(lambda _t: self._refresh_all())
        v.addWidget(self.user_combo)

        self.user_roles_list = QListWidget()
        self.user_roles_list.setMinimumHeight(90)
        v.addWidget(self.user_roles_list)

        role_row = QHBoxLayout()
        role_row.setSpacing(8)
        self.role_pick = QComboBox()
        self.role_pick.addItems(sorted(self.roles_by_id.keys()))
        role_row.addWidget(self.role_pick, 1)

        self.btn_add_role = QPushButton("Add role")
        self.btn_add_role.clicked.connect(self._add_role_to_user)
        role_row.addWidget(self.btn_add_role)

        self.btn_remove_role = QPushButton("Remove role")
        self.btn_remove_role.clicked.connect(self._remove_role_from_user)
        role_row.addWidget(self.btn_remove_role)

        v.addLayout(role_row)
        left_layout.addWidget(gb_user)

        gb_scopes = QGroupBox("3) Token scopes (OAuth style)")
        v = QVBoxLayout()
        v.setSpacing(8)
        gb_scopes.setLayout(v)

        btns = QHBoxLayout()
        btns.setSpacing(8)
        self.btn_select_required = QPushButton("Select required")
        self.btn_select_required.clicked.connect(self._select_required_scopes)
        btns.addWidget(self.btn_select_required)

        self.btn_clear_scopes = QPushButton("Clear")
        self.btn_clear_scopes.clicked.connect(self._clear_scopes)
        btns.addWidget(self.btn_clear_scopes)

        self.btn_select_all = QPushButton("Select all")
        self.btn_select_all.clicked.connect(self._select_all_scopes)
        btns.addWidget(self.btn_select_all)

        btns.addStretch(1)
        v.addLayout(btns)

        self.scopes_list = QListWidget()
        self.scopes_list.setMinimumHeight(170)
        v.addWidget(self.scopes_list, 1)

        left_layout.addWidget(gb_scopes, 1)

        self.sim_splitter.addWidget(left)

        # RIGHT: results
        right = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)
        right.setLayout(right_layout)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        self.btn_eval = QPushButton("Evaluate")
        self.btn_eval.clicked.connect(self._evaluate)
        top_row.addWidget(self.btn_eval)

        self.btn_fit = QPushButton("Fit window")
        self.btn_fit.clicked.connect(self._apply_auto_window_sizing)
        top_row.addWidget(self.btn_fit)

        self.btn_clear_out = QPushButton("Clear output")
        self.btn_clear_out.clicked.connect(self._clear_output)
        top_row.addWidget(self.btn_clear_out)

        self.btn_copy_out = QPushButton("Copy output")
        self.btn_copy_out.clicked.connect(self._copy_output)
        top_row.addWidget(self.btn_copy_out)

        top_row.addStretch(1)
        right_layout.addLayout(top_row)

        self.decision_label = QLabel("Decision: (not evaluated)")
        self.decision_label.setObjectName("DecisionLabel")
        self.decision_label.setProperty("decision", "none")
        self.decision_label.setAlignment(Qt.AlignCenter)
        self.decision_label.setMinimumHeight(50)
        right_layout.addWidget(self.decision_label)

        gb_steps = QGroupBox("Decision steps (Scopes -> RBAC -> ACL -> Final)")
        v = QVBoxLayout()
        v.setSpacing(8)
        gb_steps.setLayout(v)

        self.steps_tree = QTreeWidget()
        self.steps_tree.setHeaderLabels(["Step", "Status"])
        self.steps_tree.setColumnWidth(0, 620)
        v.addWidget(self.steps_tree)

        right_layout.addWidget(gb_steps, 1)

        gb_out = QGroupBox("Readable output")
        v = QVBoxLayout()
        v.setSpacing(8)
        gb_out.setLayout(v)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setMinimumHeight(170)
        v.addWidget(self.output)

        right_layout.addWidget(gb_out)

        self.sim_splitter.addWidget(right)
        self.sim_splitter.setStretchFactor(0, 2)
        self.sim_splitter.setStretchFactor(1, 3)

    # -------- Tab: Policies --------

    def _build_tab_policies(self) -> None:
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        self.tab_policies.setLayout(layout)

        self.pol_splitter = QSplitter(Qt.Horizontal)
        self.pol_splitter.setChildrenCollapsible(False)
        layout.addWidget(self.pol_splitter)

        left = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)
        left.setLayout(left_layout)

        gb_roles = QGroupBox("RBAC roles and permissions")
        v = QVBoxLayout()
        v.setSpacing(8)
        gb_roles.setLayout(v)

        self.roles_table = QTableWidget(0, 2)
        self.roles_table.setHorizontalHeaderLabels(["role", "permissions (action, resource)"])
        self.roles_table.verticalHeader().setVisible(False)
        self.roles_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.roles_table.setSelectionBehavior(QTableWidget.SelectRows)
        v.addWidget(self.roles_table)

        left_layout.addWidget(gb_roles, 1)

        right = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)
        right.setLayout(right_layout)

        gb_acl_edit = QGroupBox("ACL editor (allow/deny exceptions)")
        form = QFormLayout()
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)
        gb_acl_edit.setLayout(form)

        self.acl_effect = QComboBox()
        self.acl_effect.addItems(["deny", "allow"])
        form.addRow("effect", self.acl_effect)

        self.acl_subject_type = QComboBox()
        self.acl_subject_type.addItems(["role", "user"])
        self.acl_subject_type.currentTextChanged.connect(lambda _t: self._refresh_acl_subject_ids())
        form.addRow("subject_type", self.acl_subject_type)

        self.acl_subject_id = QComboBox()
        form.addRow("subject_id", self.acl_subject_id)

        self.acl_action = QComboBox()
        self.acl_action.addItems(["read", "write", "delete", "*"])
        form.addRow("action", self.acl_action)

        self.acl_resource = QLineEdit("doc:secret")
        self.acl_resource.setToolTip("Pattern examples: doc:public, doc:secret, doc:* , *")
        form.addRow("resource_pattern", self.acl_resource)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        self.btn_add_acl = QPushButton("Add ACL entry")
        self.btn_add_acl.clicked.connect(self._add_acl_entry)
        btn_row.addWidget(self.btn_add_acl)

        self.btn_remove_acl = QPushButton("Remove selected")
        self.btn_remove_acl.clicked.connect(self._remove_selected_acl_entry)
        btn_row.addWidget(self.btn_remove_acl)

        btn_row.addStretch(1)
        form.addRow(btn_row)

        right_layout.addWidget(gb_acl_edit)

        gb_acl_table = QGroupBox("ACL entries")
        v = QVBoxLayout()
        v.setSpacing(8)
        gb_acl_table.setLayout(v)

        self.acl_table = QTableWidget(0, 5)
        self.acl_table.setHorizontalHeaderLabels(["pattern_key", "effect", "subject", "action", "resource"])
        self.acl_table.verticalHeader().setVisible(False)
        self.acl_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.acl_table.setSelectionBehavior(QTableWidget.SelectRows)
        v.addWidget(self.acl_table)

        right_layout.addWidget(gb_acl_table, 1)

        hint = QLabel("Rule: ACL deny overrides everything. If no ACL matches, RBAC decides.")
        hint.setObjectName("HintLabel")
        right_layout.addWidget(hint)

        self.pol_splitter.addWidget(left)
        self.pol_splitter.addWidget(right)
        self.pol_splitter.setStretchFactor(0, 2)
        self.pol_splitter.setStretchFactor(1, 3)

    # -------- Tab: Help --------

    def _build_tab_help(self) -> None:
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        self.tab_help.setLayout(layout)

        gb = QGroupBox("How to think about it (short)")
        v = QVBoxLayout()
        v.setSpacing(8)
        gb.setLayout(v)

        txt = QPlainTextEdit()
        txt.setReadOnly(True)
        txt.setPlainText(
            "Endpoint:\n"
            "- In real APIs: method + path, e.g. GET /docs/public\n"
            "- In this demo: each endpoint also defines action/resource and required_scopes.\n"
            "\n"
            "Scopes:\n"
            "- Token-level permissions (OAuth style). Missing required scope => immediate DENY.\n"
            "\n"
            "RBAC:\n"
            "- User has roles. Roles have permissions (action, resource).\n"
            "- If any role matches => RBAC OK.\n"
            "\n"
            "ACL:\n"
            "- Object-level exceptions on resources (or patterns like doc:*).\n"
            "- deny overrides everything; allow can grant access.\n"
            "\n"
            "Typical combined usage:\n"
            "- Scopes: coarse gate\n"
            "- RBAC: default rights\n"
            "- ACL: fine-grained exceptions\n"
        )
        v.addWidget(txt)
        layout.addWidget(gb)

    # ----------------------------
    # Refresh
    # ----------------------------

    def _current_user(self) -> User:
        return self.users_by_id[self.user_combo.currentText()]

    def _current_endpoint(self) -> Endpoint:
        return self.endpoints_by_id[self.endpoint_combo.currentText()]

    def _token_scopes(self) -> Set[str]:
        scopes: Set[str] = set()
        for i in range(self.scopes_list.count()):
            it = self.scopes_list.item(i)
            if it.checkState() == Qt.Checked:
                scopes.add(it.text())
        return scopes

    def _refresh_all(self) -> None:
        self._refresh_endpoint_details()
        self._refresh_mapping_box()
        self._refresh_user_roles()
        self._refresh_scopes_list()
        self._refresh_roles_table()
        self._refresh_acl_subject_ids()
        self._refresh_acl_table()

    def _refresh_endpoint_details(self) -> None:
        ep = self._current_endpoint()
        text = (
            f"Endpoint: {ep.endpoint_id}\n"
            f"Description: {ep.description}\n\n"
            f"method: {ep.method}\n"
            f"path:   {ep.path}\n\n"
            f"action:   {ep.action}\n"
            f"resource: {ep.resource}\n"
            f"required_scopes: {', '.join(sorted(ep.required_scopes)) if ep.required_scopes else '(none)'}\n"
        )
        self.endpoint_details.setPlainText(text)

    def _refresh_mapping_box(self) -> None:
        ep = self._current_endpoint()
        text = (
            "Request (packaging):\n"
            f"- method + path: {ep.method} {ep.path}\n\n"
            "Policy inputs (stable concepts):\n"
            f"- action:   {ep.action}\n"
            f"- resource: {ep.resource}\n\n"
            "Scopes (token rights):\n"
            f"- required_scopes: {', '.join(sorted(ep.required_scopes)) if ep.required_scopes else '(none)'}\n\n"
            "Reason:\n"
            "- URLs change; policies should not hardcode URLs.\n"
            "- action/resource/scopes are reusable across APIs.\n"
        )
        self.mapping_box.setPlainText(text)

    def _refresh_user_roles(self) -> None:
        self.user_roles_list.clear()
        user = self._current_user()
        for rid in sorted(user.roles):
            self.user_roles_list.addItem(rid)

    def _refresh_scopes_list(self) -> None:
        prev = self._token_scopes()
        self.scopes_list.clear()

        ep = self._current_endpoint()
        required = set(ep.required_scopes)

        for s in sorted(self.all_scopes):
            it = QListWidgetItem(s)
            it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
            it.setCheckState(Qt.Checked if s in prev else Qt.Unchecked)

            font = it.font()
            font.setBold(s in required)
            it.setFont(font)

            if s in required:
                it.setToolTip("Required by selected endpoint.")
            else:
                it.setToolTip("Optional for this endpoint.")

            self.scopes_list.addItem(it)

    def _refresh_roles_table(self) -> None:
        rows = sorted(self.roles_by_id.keys())
        self.roles_table.setRowCount(len(rows))
        self.roles_table.setColumnCount(2)

        for r, rid in enumerate(rows):
            role = self.roles_by_id[rid]
            perms = "; ".join([f"({p.action},{p.resource})" for p in role.permissions]) if role.permissions else "(none)"
            self.roles_table.setItem(r, 0, QTableWidgetItem(rid))
            self.roles_table.setItem(r, 1, QTableWidgetItem(perms))

        self.roles_table.resizeColumnsToContents()

    def _refresh_acl_subject_ids(self) -> None:
        st = self.acl_subject_type.currentText()
        self.acl_subject_id.clear()
        if st == "user":
            self.acl_subject_id.addItems(sorted(self.users_by_id.keys()))
        else:
            self.acl_subject_id.addItems(sorted(self.roles_by_id.keys()))

    def _refresh_acl_table(self) -> None:
        rows: List[Tuple[str, str, str, str, str]] = []
        for pattern_key in sorted(self.acl_by_resource_pattern.keys()):
            for e in self.acl_by_resource_pattern[pattern_key]:
                rows.append((pattern_key, e.effect, f"{e.subject_type}:{e.subject_id}", e.action, e.resource))

        self.acl_table.setRowCount(len(rows))
        self.acl_table.setColumnCount(5)

        for r, row in enumerate(rows):
            for c, val in enumerate(row):
                self.acl_table.setItem(r, c, QTableWidgetItem(val))

        self.acl_table.resizeColumnsToContents()

    # ----------------------------
    # Actions
    # ----------------------------

    def _add_role_to_user(self) -> None:
        user = self._current_user()
        rid = self.role_pick.currentText()
        user.roles.add(rid)
        self._refresh_user_roles()

    def _remove_role_from_user(self) -> None:
        user = self._current_user()
        rid = self.role_pick.currentText()
        if rid in user.roles:
            user.roles.remove(rid)
        self._refresh_user_roles()

    def _select_required_scopes(self) -> None:
        ep = self._current_endpoint()
        required = set(ep.required_scopes)
        for i in range(self.scopes_list.count()):
            it = self.scopes_list.item(i)
            it.setCheckState(Qt.Checked if it.text() in required else Qt.Unchecked)

    def _clear_scopes(self) -> None:
        for i in range(self.scopes_list.count()):
            self.scopes_list.item(i).setCheckState(Qt.Unchecked)

    def _select_all_scopes(self) -> None:
        for i in range(self.scopes_list.count()):
            self.scopes_list.item(i).setCheckState(Qt.Checked)

    def _add_acl_entry(self) -> None:
        effect = self.acl_effect.currentText().strip()
        st = self.acl_subject_type.currentText().strip()
        sid = self.acl_subject_id.currentText().strip()
        action = self.acl_action.currentText().strip()
        res = self.acl_resource.text().strip()

        if effect not in ("allow", "deny"):
            QMessageBox.warning(self, "ACL", "effect must be allow or deny")
            return
        if st not in ("user", "role"):
            QMessageBox.warning(self, "ACL", "subject_type must be user or role")
            return
        if not sid or not action or not res:
            QMessageBox.warning(self, "ACL", "all fields must be non-empty")
            return
        if st == "user" and sid not in self.users_by_id:
            QMessageBox.warning(self, "ACL", "unknown user_id")
            return
        if st == "role" and sid not in self.roles_by_id:
            QMessageBox.warning(self, "ACL", "unknown role_id")
            return

        entry = AclEntry(effect, st, sid, action, res)
        self.acl_by_resource_pattern.setdefault(res, []).append(entry)
        self._refresh_acl_table()

    def _remove_selected_acl_entry(self) -> None:
        row = self.acl_table.currentRow()
        if row < 0:
            return

        pattern_key = self.acl_table.item(row, 0).text()
        effect = self.acl_table.item(row, 1).text()
        subject = self.acl_table.item(row, 2).text()
        action = self.acl_table.item(row, 3).text()
        resource = self.acl_table.item(row, 4).text()

        if ":" not in subject:
            return
        st, sid = subject.split(":", 1)

        entries = self.acl_by_resource_pattern.get(pattern_key, [])
        new_entries: List[AclEntry] = []
        removed = False

        for e in entries:
            if (not removed and e.effect == effect and e.subject_type == st and e.subject_id == sid and e.action == action and e.resource == resource):
                removed = True
                continue
            new_entries.append(e)

        if removed:
            if new_entries:
                self.acl_by_resource_pattern[pattern_key] = new_entries
            else:
                del self.acl_by_resource_pattern[pattern_key]
            self._refresh_acl_table()

    def _evaluate(self) -> None:
        user = self._current_user()
        ep = self._current_endpoint()
        scopes = self._token_scopes()

        allowed, steps = evaluate_access(
            user=user,
            roles_by_id=self.roles_by_id,
            acl_by_resource_pattern=self.acl_by_resource_pattern,
            endpoint=ep,
            token_scopes=scopes,
        )

        self.steps_tree.clear()
        for title, status, lines in steps:
            top = QTreeWidgetItem([title, status])
            self.steps_tree.addTopLevelItem(top)
            for ln in lines:
                child = QTreeWidgetItem([ln, ""])
                top.addChild(child)
            top.setExpanded(True)

        if allowed:
            self.decision_label.setText("Decision: ALLOW")
            self.decision_label.setProperty("decision", "allow")
        else:
            self.decision_label.setText("Decision: DENY")
            self.decision_label.setProperty("decision", "deny")

        self.decision_label.style().unpolish(self.decision_label)
        self.decision_label.style().polish(self.decision_label)

        out: List[str] = []
        out.append("=" * 76)
        out.append(f"Request:  {ep.method} {ep.path}")
        out.append(f"Mapping:  action={ep.action}, resource={ep.resource}")
        out.append("User:     " + user.user_id + " roles=[" + (", ".join(sorted(user.roles)) if user.roles else "(none)") + "]")
        out.append("Token scopes: " + (", ".join(sorted(scopes)) if scopes else "(none)"))
        out.append("Required:    " + (", ".join(sorted(ep.required_scopes)) if ep.required_scopes else "(none)"))
        out.append("Decision: " + ("ALLOW" if allowed else "DENY"))
        out.append("-" * 76)
        for title, status, lines in steps:
            out.append(f"{title} -> {status}")
            for ln in lines:
                out.append("  - " + ln)
        out.append("")
        self.output.appendPlainText("\n".join(out))

    def _clear_output(self) -> None:
        self.output.clear()
        self.decision_label.setText("Decision: (not evaluated)")
        self.decision_label.setProperty("decision", "none")
        self.decision_label.style().unpolish(self.decision_label)
        self.decision_label.style().polish(self.decision_label)
        self.steps_tree.clear()

    def _copy_output(self) -> None:
        QApplication.clipboard().setText(self.output.toPlainText())

    def _set_scopes(self, scopes: Set[str]) -> None:
        for i in range(self.scopes_list.count()):
            it = self.scopes_list.item(i)
            it.setCheckState(Qt.Checked if it.text() in scopes else Qt.Unchecked)

    def _load_scenario(self) -> None:
        name = self.scenario_combo.currentText()

        def set_user(uid: str) -> None:
            idx = self.user_combo.findText(uid)
            if idx >= 0:
                self.user_combo.setCurrentIndex(idx)

        def set_ep(eid: str) -> None:
            idx = self.endpoint_combo.findText(eid)
            if idx >= 0:
                self.endpoint_combo.setCurrentIndex(idx)

        if name == "alice reads public (allow)":
            set_user("alice")
            set_ep("GET /docs/public")
            self._refresh_all()
            self._set_scopes({"docs:read"})
        elif name == "alice reads secret (allow via ACL exception)":
            set_user("alice")
            set_ep("GET /docs/secret")
            self._refresh_all()
            self._set_scopes({"docs:read", "docs:secret"})
        elif name == "bob deletes public (deny via ACL deny)":
            set_user("bob")
            set_ep("DELETE /docs/public")
            self._refresh_all()
            self._set_scopes({"docs:delete"})
        elif name == "carol writes public (deny via missing scope unless selected)":
            set_user("carol")
            set_ep("POST /docs/public")
            self._refresh_all()
            self._set_scopes(set())
        elif name == "dave reads secret (allow: admin + scopes)":
            set_user("dave")
            set_ep("GET /docs/secret")
            self._refresh_all()
            self._set_scopes({"docs:read", "docs:secret"})
        elif name == "missing scopes example (deny in step 1)":
            set_user("dave")
            set_ep("GET /docs/secret")
            self._refresh_all()
            self._set_scopes({"docs:read"})
        else:
            return


def main() -> None:
    app = QApplication(sys.argv)
    w = MainWindow(app)
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()