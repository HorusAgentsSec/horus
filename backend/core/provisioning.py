"""
Org provisioning — the single path that turns an approved/paying customer into a
working Horus organization with an admin login.

Two entry points converge here, by design:
  • the super-admin panel (POST /admin/orgs) — manual / enterprise / Custom plan
  • the Stripe webhook (POST /billing/webhook) — self-service Pro plan, on payment

There is intentionally NO public signup: nobody provisions themselves.
"""
import logging

from backend.core.audit import log_action
from backend.core.config import settings
from backend.core.org import normalize_org_name  # raises OrgNameError
from backend.core.password import generate_temp_password
from backend.core.supabase_client import supabase

logger = logging.getLogger(__name__)


class ProvisionError(Exception):
    """The customer can't be provisioned (e.g. already belongs to an org)."""


def provision_org(
    org_name, admin_email, *, plan="custom", source="manual", actor_id=None,
    stripe_customer_id=None, stripe_subscription_id=None, seats=None,
):
    """Create an org + its first admin user and email them a temporary password.

    Guards against duplicates: if the email already owns a profile, raises
    ProvisionError so a double click (admin panel) or a redelivered webhook (Stripe)
    can't create a second org for the same customer.

    Billing fields (stripe_customer_id / stripe_subscription_id / seats) are stored in
    the org's settings jsonb so the Customer Portal and seat enforcement can use them.

    Returns {org_id, user_id, email, temp_password|None, emailed}.
    """
    name = normalize_org_name(org_name)  # may raise OrgNameError
    email = admin_email.strip().lower()

    # Reuse an existing auth user (past demo/invite) if present; else create one.
    # Either way the user must not already have a profile.
    all_users = supabase.auth.admin.list_users()
    existing = next((u for u in all_users if (u.email or "").lower() == email), None)

    if existing:
        if supabase.table("profiles").select("id").eq("id", existing.id).execute().data:
            raise ProvisionError(f"{email} already belongs to an organization")
        user_id = existing.id
        temp_password = None  # keeps its existing password
    else:
        temp_password = generate_temp_password()
        created = supabase.auth.admin.create_user({
            "email": email,
            "password": temp_password,
            "email_confirm": True,  # skip Supabase's confirmation email (its Site URL is the app)
        })
        user_id = created.user.id

    org_settings = {"plan": plan, "source": source}
    if stripe_customer_id:
        org_settings["stripe_customer_id"] = stripe_customer_id
    if stripe_subscription_id:
        org_settings["stripe_subscription_id"] = stripe_subscription_id
    if seats is not None:
        org_settings["seats"] = seats

    org_id = supabase.table("organizations").insert({
        "name": name,
        "settings": org_settings,
    }).execute().data[0]["id"]

    supabase.table("profiles").insert({
        "id": user_id,
        "org_id": org_id,
        "role": "admin",
        "full_name": email.split("@")[0],
        # New accounts must replace the random temp password on first sign-in.
        "must_change_password": temp_password is not None,
    }).execute()

    # Membership is the source of truth for belonging; the profile above just mirrors this
    # as the active org. The founding admin is a member of their own org.
    supabase.table("memberships").upsert(
        {"user_id": user_id, "org_id": org_id, "role": "admin"},
        on_conflict="user_id,org_id",
    ).execute()

    emailed = _send_welcome_email(email, name, temp_password)

    log_action(
        org_id, actor_id or user_id, "org.provisioned",
        entity_type="organization", entity_id=org_id,
        metadata={"name": name, "admin_email": email, "plan": plan, "source": source},
    )
    return {
        "org_id": org_id, "user_id": user_id, "email": email,
        "temp_password": temp_password, "emailed": emailed,
    }


def add_member(org_id, email, role, *, actor_id=None):
    """Add a user to an EXISTING org as a member (the multi-org path).

    Unlike provision_org, this never creates an org and never overwrites the active org of a
    user who already belongs elsewhere: it only grants a membership. A brand-new user (no
    profile yet) also gets a profile with this org active, so they can sign in.

    Returns {org_id, user_id, email, temp_password|None}.
    """
    email = email.strip().lower()
    if role not in ("admin", "analyst", "viewer"):
        raise ProvisionError(f"Invalid role: {role}")

    org = supabase.table("organizations").select("name").eq("id", org_id).single().execute().data
    if not org:
        raise ProvisionError("Organization not found")

    all_users = supabase.auth.admin.list_users()
    existing = next((u for u in all_users if (u.email or "").lower() == email), None)
    temp_password = None
    if existing:
        user_id = existing.id
    else:
        temp_password = generate_temp_password()
        created = supabase.auth.admin.create_user({
            "email": email, "password": temp_password, "email_confirm": True,
        })
        user_id = created.user.id

    # A profile is required to sign in. Create one (with this org active) only if absent —
    # never touch the profile of a user who already belongs to another org.
    has_profile = supabase.table("profiles").select("id").eq("id", user_id).execute().data
    if not has_profile:
        supabase.table("profiles").insert({
            "id": user_id, "org_id": org_id, "role": role,
            "full_name": email.split("@")[0],
            "must_change_password": temp_password is not None,
        }).execute()

    # The membership itself (source of truth). Idempotent; reactivates a soft-deleted one.
    supabase.table("memberships").upsert(
        {"user_id": user_id, "org_id": org_id, "role": role, "deleted_at": None},
        on_conflict="user_id,org_id",
    ).execute()

    if temp_password:
        _send_welcome_email(email, org["name"], temp_password)

    log_action(
        org_id, actor_id or user_id, "org.member_added",
        entity_type="organization", entity_id=org_id,
        metadata={"email": email, "role": role},
    )
    return {"org_id": org_id, "user_id": user_id, "email": email, "temp_password": temp_password}


def _send_welcome_email(email, org_name, temp_password):
    """Best-effort welcome email with the login link and temp password.

    Never raises: provisioning must succeed even if SMTP is down — the super-admin can
    read the returned temp_password and relay it manually. Returns True if sent.
    """
    login_url = f"{settings.app_base_url.rstrip('/')}/login"
    if temp_password:
        body = (
            f'Welcome to Horus.\n\n'
            f'Your organization "{org_name}" is ready.\n\n'
            f'Sign in at: {login_url}\n'
            f'Email: {email}\n'
            f'Temporary password: {temp_password}\n\n'
            f"You'll be asked to set a new password on first sign-in.\n"
        )
    else:
        body = (
            f'Welcome to Horus.\n\n'
            f'Your organization "{org_name}" is ready and linked to your existing account.\n\n'
            f'Sign in at: {login_url}\n'
            f'Email: {email}\n'
        )
    try:
        from backend.core.notify import send_email
        send_email({"to": [email]}, "Your Horus account is ready", body)
        return True
    except Exception as e:  # noqa: BLE001 — best-effort, must not break provisioning
        logger.warning("welcome email to %s failed: %s", email, e)
        return False
