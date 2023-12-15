from typing import Optional

import pydantic
from pydantic import root_validator


class ModifiedAESIn(pydantic.BaseModel):
    key: Optional[str]
    plain_text: Optional[str]
    cipher_text: Optional[str]

    @root_validator
    def check_values(cls, values):
        if values.get("plain_text") is not None and values.get("cipher_text") is None and values.get("key") is None:
            raise Exception("If plain_text is provided, and cipher_text not, the encryption key must be provided")
        return values
