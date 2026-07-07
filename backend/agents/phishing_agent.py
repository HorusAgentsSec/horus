"""
PhishingAgent — generates contextually realistic phishing simulation emails.

The differentiator vs. generic phishing tools: the agent receives the org's
actual asset inventory (subdomains, detected technologies) and uses that context
to craft lures that reference real internal systems. A lure mentioning
crm.bse.eu is far more convincing to an employee than a generic "verify your
account" template — and therefore a far more useful training signal.

Output: subject, HTML body, and a pre-built honeypot URL.
Never used offensively; only called for internal simulation campaigns.
"""

import logging

from backend.agents.base import BaseAgent
from backend.agents.state import ScanState

logger = logging.getLogger(__name__)

_SYSTEM = """You are a cybersecurity awareness trainer generating INTERNAL phishing simulation emails
for authorized security testing. Your goal is to create realistic but harmless lures that help
employees recognise social-engineering attacks.

Rules:
- Use the provided asset context (real internal hostnames/apps) to make the lure plausible.
- Never include actual malware, exploits, or credential-harvesting beyond the provided tracking URL.
- The email must look legitimate enough to train employees, not obviously fake.
- Output ONLY valid JSON matching the schema below — no markdown, no extra text.

Output schema:
{
  "subject": "<email subject line>",
  "body_html": "<full HTML email body with the tracking_url as the single CTA link>",
  "pretext": "<one sentence describing the social-engineering pretext used>"
}"""

_TEMPLATE_SYSTEM = """You are a cybersecurity awareness trainer generating INTERNAL phishing simulation email TEMPLATES.
Templates use placeholders instead of real employee data. These templates will be saved and reused across campaigns.

Rules:
- Use {{employee_name}} where the recipient's name appears.
- Use {{tracking_url}} as the href for the single call-to-action link/button.
- Use {{employee_email}} if the employee's email address is needed.
- The HTML must be self-contained, professional-looking, and realistic.
- Never include actual malware or exploits.
- Output ONLY valid JSON — no markdown, no extra text.

Output schema:
{
  "subject": "<email subject line>",
  "body_html": "<full HTML email body using {{employee_name}} and {{tracking_url}} placeholders>",
  "pretext": "<one sentence describing the social-engineering scenario>"
}"""


class PhishingAgent(BaseAgent):
    agent_type = "phishing"

    def run(self, state: ScanState) -> ScanState:
        raise NotImplementedError("use generate_email() directly")

    def generate_email(
        self,
        employee_name: str,
        employee_email: str,
        objective: str,
        asset_context: list[dict],
        tracking_url: str,
        org_name: str = "",
    ) -> dict:
        """
        Generate a phishing simulation email for one target.

        Args:
            employee_name: display name of the recipient
            employee_email: email address (used for personalisation only)
            objective: 'click' | 'credentials' | 'report'
            asset_context: list of asset dicts with at least 'name' and optionally 'type'
            tracking_url: the honeypot URL to embed as the CTA
            org_name: organisation name for branding context

        Returns:
            dict with keys: subject, body_html, pretext
        """
        assets_summary = "\n".join(
            f"- {a.get('name', 'unknown')} (type: {a.get('asset_type') or a.get('type') or 'host'})"
            for a in asset_context[:5]  # cap context to 5 assets
        ) or "- (no specific assets provided)"

        objective_guidance = {
            "click": "The lure should get the employee to click a link (urgency/curiosity angle).",
            "credentials": "The lure should prompt the employee to log in (expired session / security alert).",
            "report": (
                "The lure should be a suspicious email that a security-aware employee would report. "
                "Make it slightly off — wrong sender domain, unusual request."
            ),
        }.get(objective, "")

        user_content = f"""Generate a phishing simulation email for:
Employee: {employee_name} <{employee_email}>
Organisation: {org_name or 'the company'}
Objective: {objective} — {objective_guidance}

Internal assets / systems in scope for context:
{assets_summary}

Honeypot tracking URL to embed as the CTA button/link: {tracking_url}

Use one of the assets above as the main lure context (e.g. "Your session on crm.example.com has expired").
Personalise with the employee's name. Output valid JSON only."""

        try:
            result, tokens = self.call_llm_json(_SYSTEM, user_content, max_tokens=1500)
            if isinstance(result, dict) and "subject" in result and "body_html" in result:
                return result
            logger.warning("PhishingAgent unexpected JSON shape: %s", list(result.keys()) if isinstance(result, dict) else type(result))
        except Exception as e:
            logger.error("PhishingAgent LLM call failed: %s", e)

        # Fallback template when LLM fails
        asset_name = asset_context[0]["name"] if asset_context else "the platform"
        return {
            "subject": f"[Security Notice] Your session on {asset_name} requires verification",
            "body_html": (
                f"<p>Hi {employee_name},</p>"
                f"<p>Your access to <strong>{asset_name}</strong> has been flagged for a security review. "
                f"Please verify your identity to avoid service interruption.</p>"
                f'<p><a href="{tracking_url}" style="background:#0055cc;color:#fff;padding:10px 20px;'
                f'text-decoration:none;border-radius:4px">Verify Now</a></p>'
                f"<p>If you did not request this, contact IT security immediately.</p>"
            ),
            "pretext": f"Fake security alert about {asset_name} to test click-through rate.",
        }

    def generate_template(
        self,
        objective: str,
        scenario: str,
        org_name: str = "",
    ) -> dict:
        """
        Generate a reusable phishing template with placeholders.

        Returns dict with keys: subject, body_html, pretext
        Placeholders in body_html: {{employee_name}}, {{tracking_url}}, {{employee_email}}
        """
        objective_guidance = {
            "click": "The lure should get the reader to click a link (urgency/curiosity angle).",
            "credentials": "The lure should prompt the reader to log in (expired session / security alert).",
            "report": "The lure should look slightly suspicious — a security-aware employee would report it.",
        }.get(objective, "")

        user_content = f"""Generate a phishing simulation email TEMPLATE for:
Organisation: {org_name or 'the company'}
Objective: {objective} — {objective_guidance}
Scenario: {scenario}

Use {{{{employee_name}}}} as the recipient name placeholder.
Use {{{{tracking_url}}}} as the href for the call-to-action link/button.
Output valid JSON only."""

        try:
            result, _ = self.call_llm_json(_TEMPLATE_SYSTEM, user_content, max_tokens=1500)
            if isinstance(result, dict) and "subject" in result and "body_html" in result:
                return result
            logger.warning("PhishingAgent.generate_template unexpected JSON: %s", result)
        except Exception as e:
            logger.error("PhishingAgent.generate_template LLM call failed: %s", e)

        return {
            "subject": f"[Security Notice] Action required — {scenario[:60]}",
            "body_html": (
                "<p>Hi {{employee_name}},</p>"
                f"<p>{scenario}</p>"
                '<p><a href="{{tracking_url}}" style="background:#0055cc;color:#fff;padding:10px 20px;'
                'text-decoration:none;border-radius:4px">Take Action</a></p>'
                "<p>If you did not expect this, contact IT security immediately.</p>"
            ),
            "pretext": scenario,
        }

    @staticmethod
    def apply_template(body_html: str, subject: str, employee_name: str, employee_email: str, tracking_url: str) -> dict:
        """Replace template placeholders with real values for a specific target."""
        replacements = {
            "{{employee_name}}": employee_name,
            "{{employee_email}}": employee_email,
            "{{tracking_url}}": tracking_url,
        }
        rendered_body = body_html
        rendered_subject = subject
        for placeholder, value in replacements.items():
            rendered_body = rendered_body.replace(placeholder, value)
            rendered_subject = rendered_subject.replace(placeholder, value)
        return {"subject": rendered_subject, "body_html": rendered_body}
