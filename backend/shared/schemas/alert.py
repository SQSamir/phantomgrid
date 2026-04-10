from datetime import datetime
from pydantic import BaseModel

class AlertOut(BaseModel):
    id: str
    severity: str
    status: str
    title: str
    summary: str
    source_ip: str | None = None
    first_seen_at: datetime
