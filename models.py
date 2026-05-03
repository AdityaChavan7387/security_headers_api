from pydantic import BaseModel
from typing import Optional

class ScanRequest(BaseModel):
    url: str
    follow_redirects: Optional[bool] = True
    timeout: Optional[int] = 10
    include_raw_headers: Optional[bool] = False