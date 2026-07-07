from abc import ABC, abstractmethod
from backend.agents.state import RawFinding


class BaseScanner(ABC):
    @abstractmethod
    def scan(
        self,
        host: str,
        port: int | None = None,
        *,
        scan_id: str | None = None,
    ) -> list[RawFinding]:
        pass
