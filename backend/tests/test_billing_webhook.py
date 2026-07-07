"""
Tests for the Stripe webhook (backend/api/billing.py) — the only unauthenticated write path in
the app (registration is closed; this is how an Org gets created). Covers: signature rejection,
successful provisioning, redelivery idempotency (Stripe retries webhooks — a duplicate delivery
must not blow up or double-provision), and subscription seat/status sync.
"""

from unittest.mock import MagicMock, patch

import pytest
import stripe
from fastapi.testclient import TestClient

from backend.api import billing
from backend.core.config import settings
from backend.core.provisioning import ProvisionError
from backend.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def _webhook_configured(monkeypatch):
    monkeypatch.setattr(settings, "stripe_webhook_secret", "whsec_test")


def _post_event(event: dict):
    with patch("stripe.Webhook.construct_event", return_value=event):
        return client.post(
            "/api/billing/webhook",
            content=b"{}",
            headers={"Stripe-Signature": "t=1,v1=fake"},
        )


def test_webhook_disabled_without_configured_secret(monkeypatch):
    monkeypatch.setattr(settings, "stripe_webhook_secret", "")
    resp = client.post("/api/billing/webhook", content=b"{}", headers={"Stripe-Signature": "x"})
    assert resp.status_code == 503


def test_webhook_rejects_invalid_signature():
    with patch("stripe.Webhook.construct_event", side_effect=stripe.error.SignatureVerificationError("bad sig", "sig")):
        resp = client.post(
            "/api/billing/webhook", content=b"{}", headers={"Stripe-Signature": "t=1,v1=bad"}
        )
    assert resp.status_code == 400


def test_checkout_completed_provisions_org():
    event = {
        "type": "checkout.session.completed",
        "data": {"object": {
            "customer_details": {"email": "New.Admin@Acme.com"},
            "metadata": {"plan": "pro", "org_name": "Acme"},
            "customer": "cus_123",
            "subscription": None,
        }},
    }
    with patch.object(billing, "provision_org", return_value={"org_id": "org-1"}) as mock_provision:
        resp = _post_event(event)

    assert resp.status_code == 200
    assert resp.json()["status"] == "provisioned"
    mock_provision.assert_called_once_with(
        "Acme", "New.Admin@Acme.com", plan="pro", source="stripe",
        stripe_customer_id="cus_123", stripe_subscription_id=None, seats=None,
    )


def test_checkout_completed_without_email_does_not_provision():
    event = {
        "type": "checkout.session.completed",
        "data": {"object": {"customer_details": {}, "metadata": {}}},
    }
    with patch.object(billing, "provision_org") as mock_provision:
        resp = _post_event(event)

    assert resp.status_code == 200
    assert resp.json()["status"] == "no_email"
    mock_provision.assert_not_called()


def test_checkout_completed_redelivery_is_idempotent():
    # Stripe retries webhooks on any non-2xx or timeout. A redelivered
    # checkout.session.completed for an already-provisioned customer must return 200
    # (not 500), or Stripe will keep retrying it forever.
    event = {
        "type": "checkout.session.completed",
        "data": {"object": {
            "customer_details": {"email": "again@acme.com"},
            "metadata": {},
            "customer": "cus_123",
            "subscription": None,
        }},
    }
    with patch.object(billing, "provision_org", side_effect=ProvisionError("already belongs")):
        resp = _post_event(event)

    assert resp.status_code == 200
    assert resp.json()["status"] == "already_provisioned"


def test_subscription_updated_syncs_seats_and_status():
    event = {
        "type": "customer.subscription.updated",
        "data": {"object": {
            "id": "sub_1",
            "status": "active",
            "items": {"data": [{"quantity": 7}]},
        }},
    }
    mock_supabase = MagicMock()
    mock_supabase.table.return_value.select.return_value.eq.return_value.execute.return_value.data = [
        {"id": "org-1", "settings": {"plan": "pro"}}
    ]
    with patch.object(billing, "supabase", mock_supabase):
        resp = _post_event(event)

    assert resp.status_code == 200
    body = resp.json()
    assert body == {"status": "synced", "org_id": "org-1", "seats": 7, "subscription_status": "active"}
    updated_settings = mock_supabase.table.return_value.update.call_args[0][0]["settings"]
    assert updated_settings["seats"] == 7
    assert updated_settings["subscription_status"] == "active"
    assert "subscription_canceled_at" not in updated_settings


def test_subscription_deleted_marks_org_canceled():
    event = {"type": "customer.subscription.deleted", "data": {"object": {"id": "sub_1"}}}
    mock_supabase = MagicMock()
    mock_supabase.table.return_value.select.return_value.eq.return_value.execute.return_value.data = [
        {"id": "org-1", "settings": {}}
    ]
    with patch.object(billing, "supabase", mock_supabase):
        resp = _post_event(event)

    assert resp.status_code == 200
    assert resp.json() == {"status": "canceled", "org_id": "org-1"}
    updated_settings = mock_supabase.table.return_value.update.call_args[0][0]["settings"]
    assert updated_settings["subscription_status"] == "canceled"
    assert "subscription_canceled_at" in updated_settings


def test_unhandled_event_type_is_ignored():
    resp = _post_event({"type": "payment_intent.succeeded", "data": {"object": {}}})
    assert resp.status_code == 200
    assert resp.json() == {"ignored": "payment_intent.succeeded"}
