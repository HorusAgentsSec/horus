"""
Shared cloud-audit primitives: the provider-agnostic CloudFinding and the sensitive-port map.

Both AWS and GCP check modules build CloudFinding objects; only the `provider` field and the
resource id differ. Keeping it here (instead of per-provider) means the persistence layer and any
future provider share one shape.
"""

from dataclasses import dataclass

# Inbound ports that should essentially never be open to the whole internet. Shared by AWS security
# groups and GCP firewall rules. Map port -> human label.
SENSITIVE_PORTS = {
    22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 1433: "MSSQL",
    11211: "Memcached", 5601: "Kibana",
}


@dataclass(frozen=True)
class CloudFinding:
    check_id: str           # stable id, e.g. "s3_public_bucket"
    title: str
    severity: str           # critical | high | medium | low | info
    resource: str           # the specific resource — part of the dedup key
    description: str
    remediation: str
    service: str            # s3 | iam | ec2 | codebuild | storage | compute | cloudsql | cloudbuild …
    category: str           # cspm | cicd
    provider: str = "aws"   # aws | gcp — scopes the dedup key so providers never collide

    @property
    def dedup_key(self) -> str:
        """Stable per-resource key; the audit turns this into the finding fingerprint."""
        return f"{self.provider}:{self.check_id}:{self.resource}"
