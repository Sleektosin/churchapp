"""Centralized Role-Based Access Control (RBAC).

This module is the single source of truth for:
  * the roles the application recognises,
  * the permissions each role grants,
  * the decorators used to protect routes, and
  * helpers used by templates / models to check access.

Roles are stored in the database (``Role`` model); this module maps those
role *names* to a set of fine-grained permissions so that route protection
can be expressed in terms of *what a user may do* rather than *which role
they hold*.
"""

from functools import wraps

from flask import abort, redirect, url_for, flash
from flask_login import current_user


# --------------------------------------------------------------------------
# Roles
# --------------------------------------------------------------------------
ROLE_ADMIN = 'Admin'
ROLE_USER = 'User'
ROLE_GUEST = 'Guest'

# Roles seeded on startup: (name, description)
DEFAULT_ROLES = [
    (ROLE_ADMIN, 'Full administrative access to the application'),
    (ROLE_USER, 'Standard member access'),
    (ROLE_GUEST, 'Limited, read-only access'),
]

# Core roles that are referenced by the permission matrix and therefore
# cannot be renamed or deleted from the UI.
PROTECTED_ROLE_NAMES = {ROLE_ADMIN, ROLE_USER, ROLE_GUEST}


# --------------------------------------------------------------------------
# Permissions
# --------------------------------------------------------------------------
class Permission:
    VIEW_DASHBOARD = 'view_dashboard'
    VIEW_ANALYTICS = 'view_analytics'
    MANAGE_USERS = 'manage_users'
    MANAGE_SESSIONS = 'manage_sessions'
    MANAGE_INVENTORY = 'manage_inventory'
    MANAGE_MAINTENANCE = 'manage_maintenance'
    MANAGE_BIOMETRICS = 'manage_biometrics'   # enroll / de-enroll fingerprints
    RESET_PASSWORDS = 'reset_passwords'        # admin reset of a user's password
    RESET_EMAILS = 'reset_emails'              # admin reset of a user's email
    MANAGE_ROLES = 'manage_roles'              # create / edit / delete roles
    SELF_CHECKIN = 'self_checkin'


# Which permissions each role grants.
ROLE_PERMISSIONS = {
    ROLE_ADMIN: {
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_ANALYTICS,
        Permission.MANAGE_USERS,
        Permission.MANAGE_SESSIONS,
        Permission.MANAGE_INVENTORY,
        Permission.MANAGE_MAINTENANCE,
        Permission.MANAGE_BIOMETRICS,
        Permission.RESET_PASSWORDS,
        Permission.RESET_EMAILS,
        Permission.MANAGE_ROLES,
        Permission.SELF_CHECKIN,
    },
    ROLE_USER: {
        Permission.VIEW_DASHBOARD,
        Permission.SELF_CHECKIN,
    },
    ROLE_GUEST: {
        Permission.VIEW_DASHBOARD,
    },
}


# Human-friendly labels for each permission (used by the roles UI).
PERMISSION_LABELS = {
    Permission.VIEW_DASHBOARD: 'View Dashboard',
    Permission.VIEW_ANALYTICS: 'View Analytics',
    Permission.MANAGE_USERS: 'Manage Users',
    Permission.MANAGE_SESSIONS: 'Manage Sessions',
    Permission.MANAGE_INVENTORY: 'Manage Inventory',
    Permission.MANAGE_MAINTENANCE: 'Manage Maintenance',
    Permission.MANAGE_BIOMETRICS: 'Manage Biometrics',
    Permission.RESET_PASSWORDS: 'Reset Passwords',
    Permission.RESET_EMAILS: 'Reset Emails',
    Permission.MANAGE_ROLES: 'Manage Roles',
    Permission.SELF_CHECKIN: 'Self Check-in',
}
ALL_PERMISSIONS = list(PERMISSION_LABELS.keys())


def parse_permissions(raw):
    """Parse a stored CSV permission string into a set of valid permissions."""
    if not raw:
        return set()
    return {p.strip() for p in raw.split(',') if p.strip() in PERMISSION_LABELS}


def serialize_permissions(perms):
    """Serialize an iterable of permissions to a canonical CSV string."""
    wanted = set(perms)
    return ','.join(p for p in ALL_PERMISSIONS if p in wanted)


def role_effective_permissions(role):
    """The permissions a role actually grants.

    * The Admin role always grants *all* permissions (cannot be locked out).
    * Any other role uses its DB-stored permissions when set; otherwise it
      falls back to the code-defined default in ``ROLE_PERMISSIONS``.
    """
    if role is None:
        return set()
    if role.name == ROLE_ADMIN:
        return set(ALL_PERMISSIONS)
    raw = getattr(role, 'permissions', None)
    if raw is not None:
        return parse_permissions(raw)
    return set(ROLE_PERMISSIONS.get(role.name, set()))


def permissions_for_roles(role_names):
    """Union of *default* permissions for an iterable of role names (matrix only)."""
    granted = set()
    for name in role_names:
        granted |= ROLE_PERMISSIONS.get(name, set())
    return granted


def user_has_permission(user, permission):
    """True if any of the user's roles grants ``permission`` (DB-aware)."""
    if user is None or not getattr(user, 'is_authenticated', False):
        return False
    for role in getattr(user, 'roles', []):
        if permission in role_effective_permissions(role):
            return True
    return False


def user_has_role(user, *role_names):
    if user is None or not getattr(user, 'is_authenticated', False):
        return False
    held = {r.name for r in getattr(user, 'roles', [])}
    return any(name in held for name in role_names)


# --------------------------------------------------------------------------
# Route decorators
# --------------------------------------------------------------------------
def _deny():
    """Uniform denial: send anonymous users to login, others to a 403."""
    if not current_user.is_authenticated:
        return redirect(url_for('views.login'))
    flash('You do not have permission to perform that action.', category='error')
    abort(403)


def roles_required(*role_names):
    """Allow only users holding at least one of ``role_names``."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not user_has_role(current_user, *role_names):
                return _deny()
            return f(*args, **kwargs)
        return wrapper
    return decorator


def permission_required(*permissions):
    """Allow only users whose roles grant *all* of ``permissions``."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not all(user_has_permission(current_user, p) for p in permissions):
                return _deny()
            return f(*args, **kwargs)
        return wrapper
    return decorator


def admin_required(f):
    """Convenience decorator: restrict to the Admin role."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not user_has_role(current_user, ROLE_ADMIN):
            return _deny()
        return f(*args, **kwargs)
    return wrapper


# --------------------------------------------------------------------------
# Seeding
# --------------------------------------------------------------------------
def ensure_role_permissions_column(db):
    """Idempotently add the ``permissions`` column to the role table.

    Lets custom roles store their granted permissions without requiring a
    manual migration. Safe to run on every startup. Must run *before* any
    Role query (the model maps the column).
    """
    from sqlalchemy import text
    dialect = db.engine.dialect.name

    # 1) Add the permissions column if it is missing
    try:
        if dialect == 'postgresql':
            with db.engine.begin() as conn:
                conn.execute(text('ALTER TABLE role ADD COLUMN IF NOT EXISTS permissions TEXT'))
        else:
            # SQLite / others: no ADD COLUMN IF NOT EXISTS — check first
            with db.engine.connect() as conn:
                cols = [row[1] for row in conn.execute(text('PRAGMA table_info(role)'))]
            if 'permissions' not in cols:
                with db.engine.begin() as conn:
                    conn.execute(text('ALTER TABLE role ADD COLUMN permissions TEXT'))
        print('[RBAC] role.permissions column ensured')
    except Exception as exc:  # pragma: no cover - never block startup
        print(f'[RBAC] ensure permissions column skipped: {exc}')

    # 2) Realign the id sequence (Postgres) so new role inserts never collide
    #    with an existing primary key when the sequence has drifted.
    if dialect == 'postgresql':
        try:
            with db.engine.begin() as conn:
                conn.execute(text(
                    "SELECT setval(pg_get_serial_sequence('role','id'), "
                    "GREATEST((SELECT COALESCE(MAX(id), 1) FROM role), 1))"
                ))
        except Exception as exc:  # pragma: no cover
            print(f'[RBAC] role id sequence realign skipped: {exc}')


def seed_roles(db, role_model):
    """Idempotently ensure the default roles exist in the database."""
    try:
        created = False
        for name, description in DEFAULT_ROLES:
            if not role_model.query.filter_by(name=name).first():
                db.session.add(role_model(name=name, description=description))
                created = True
        if created:
            db.session.commit()
    except Exception as exc:  # pragma: no cover - never block startup on seeding
        db.session.rollback()
        print(f'[RBAC] Role seeding skipped: {exc}')
