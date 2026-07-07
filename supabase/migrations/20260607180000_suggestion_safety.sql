-- Remediation safety tier on each suggestion.
--
-- The RiskManager now classifies every remediation by blast radius (reversible / disruptive /
-- destructive) and uses it as a hard ceiling on execution autonomy — a destructive fix can never be
-- auto-applied, even if a permission policy allows it. Persisting the tier lets the review UI flag
-- "this is a destructive command — review carefully" and is the audit record behind the autonomy
-- decision. jsonb not needed; it's a single enum-like string.

alter table agent_suggestions add column if not exists safety_tier text;
