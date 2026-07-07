"""
Stripe billing — webhook (auto-provision + seat sync) and Customer Portal access.

Self-serve half of the business model:
  - checkout.session.completed   → provision the org (stores customer/subscription/seats)
  - customer.subscription.updated → sync the seat count (and status) onto the org
  - customer.subscription.deleted → mark the org's subscription canceled
  - POST /billing/portal          → open the Stripe Customer Portal for the org's admin,
                                     where they change seats / payment method / cancel.

Stripe handles proration automatically: lowering seats credits the next invoice, so the
customer "pays less next month" with no code on our side. We only mirror the seat count
into the org so team-invite enforcement can respect it.
"""
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from backend.api.deps import require_role
from backend.core.config import settings
from backend.core.org import OrgNameError
from backend.core.provisioning import ProvisionError, provision_org
from backend.core.supabase_client import supabase

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/billing", tags=["billing"])


def _stripe():
    """Import stripe lazily and set the API key. Raises 503 if billing isn't configured."""
    if not settings.stripe_secret_key:
        raise HTTPException(status_code=503, detail="Billing not configured")
    import stripe
    stripe.api_key = settings.stripe_secret_key
    return stripe


def _seats_from_subscription(sub) -> int | None:
    try:
        return sub["items"]["data"][0].get("quantity")
    except (KeyError, IndexError, TypeError):
        return None


def _org_by_subscription(sub_id: str):
    rows = (
        supabase.table("organizations")
        .select("id, settings")
        .eq("settings->>stripe_subscription_id", sub_id)
        .execute()
        .data
        or []
    )
    return rows[0] if rows else None


def _sync_subscription(sub: dict) -> dict:
    """Mirror a subscription's seat count + status onto its org. No-op if unknown."""
    org = _org_by_subscription(sub.get("id"))
    if not org:
        logger.info("subscription %s has no matching org; ignoring", sub.get("id"))
        return {"status": "no_org"}
    new_settings = {**(org.get("settings") or {})}
    seats = _seats_from_subscription(sub)
    if seats is not None:
        new_settings["seats"] = seats
    status_ = sub.get("status")
    new_settings["subscription_status"] = status_
    # Stamp when the subscription first lapses (canceled/unpaid) — the grace clock starts here.
    # Clear it once the customer recovers (active/trialing/past_due) so access is restored.
    if status_ in ("canceled", "unpaid"):
        new_settings.setdefault("subscription_canceled_at", datetime.now(timezone.utc).isoformat())
    else:
        new_settings.pop("subscription_canceled_at", None)
    supabase.table("organizations").update({"settings": new_settings}).eq("id", org["id"]).execute()
    return {"status": "synced", "org_id": org["id"], "seats": seats, "subscription_status": status_}


@router.post("/webhook")
async def stripe_webhook(request: Request, stripe_signature: str = Header(None, alias="Stripe-Signature")):
    if not settings.stripe_webhook_secret:
        raise HTTPException(status_code=503, detail="Billing not configured")

    import stripe

    payload = await request.body()
    try:
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, settings.stripe_webhook_secret
        )
    except Exception as e:  # bad signature or malformed body
        raise HTTPException(status_code=400, detail=f"Invalid webhook: {e}")

    etype = event["type"]
    obj = event["data"]["object"]

    if etype == "checkout.session.completed":
        return _handle_checkout_completed(obj)
    if etype == "customer.subscription.updated":
        return _sync_subscription(obj)
    if etype == "customer.subscription.deleted":
        org = _org_by_subscription(obj.get("id"))
        if org:
            new_settings = {**(org.get("settings") or {}), "subscription_status": "canceled"}
            new_settings.setdefault("subscription_canceled_at", datetime.now(timezone.utc).isoformat())
            supabase.table("organizations").update({"settings": new_settings}).eq("id", org["id"]).execute()
            return {"status": "canceled", "org_id": org["id"]}
        return {"status": "no_org"}

    return {"ignored": etype}


def _handle_checkout_completed(session: dict) -> dict:
    email = (session.get("customer_details") or {}).get("email") or session.get("customer_email")
    if not email:
        logger.warning("checkout.session.completed without an email; cannot provision")
        return {"status": "no_email"}

    meta = session.get("metadata") or {}
    plan = meta.get("plan", "pro")
    org_name = meta.get("org_name") or email.split("@")[-1]  # fall back to email domain

    customer_id = session.get("customer")
    sub_id = session.get("subscription")
    seats = None
    if sub_id and settings.stripe_secret_key:
        try:
            sub = _stripe().Subscription.retrieve(sub_id)
            seats = _seats_from_subscription(sub)
        except Exception as e:  # noqa: BLE001 — seats are best-effort; provisioning must proceed
            logger.warning("could not read seats for subscription %s: %s", sub_id, e)

    try:
        result = provision_org(
            org_name, email, plan=plan, source="stripe",
            stripe_customer_id=customer_id, stripe_subscription_id=sub_id, seats=seats,
        )
        return {"status": "provisioned", "org_id": result["org_id"], "seats": seats}
    except ProvisionError as e:
        logger.info("stripe webhook: %s", e)
        return {"status": "already_provisioned"}
    except OrgNameError as e:
        logger.error("stripe webhook: bad org name %r: %s", org_name, e)
        return {"status": "error", "detail": str(e)}


@router.post("/portal")
async def billing_portal(user: dict = Depends(require_role("admin"))):
    """Open the Stripe Customer Portal for the caller's org (admins only)."""
    org = (
        supabase.table("organizations")
        .select("settings").eq("id", user["org_id"]).single().execute().data
    )
    customer_id = (org.get("settings") or {}).get("stripe_customer_id") if org else None
    if not customer_id:
        raise HTTPException(status_code=400, detail="This organization has no Stripe billing account.")

    stripe = _stripe()
    kwargs = {"customer": customer_id, "return_url": f"{settings.app_base_url.rstrip('/')}/settings"}
    if settings.stripe_portal_config_id:
        kwargs["configuration"] = settings.stripe_portal_config_id
    sess = stripe.billing_portal.Session.create(**kwargs)
    return {"url": sess.url}
