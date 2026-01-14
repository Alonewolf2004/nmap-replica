from typing import List, Optional
from pydantic import BaseModel, Field, validator

class ScanConfig(BaseModel):
    """
    Validation model for scan parameters.
    Enforces strict types and safe ranges before execution.
    """
    target_ip: str
    ports: List[int] = Field(..., min_items=1)
    timeout: float = Field(1.5, gt=0, le=10.0)
    concurrency: int = Field(500, ge=1, le=5000)
    output_file: Optional[str] = None

    @validator('ports')
    def validate_ports(cls, v):
        # Filter invalid ports and sort
        valid = sorted(list(set(p for p in v if 1 <= p <= 65535)))
        if not valid:
            raise ValueError("No valid ports found in range 1-65535")
        return valid
