"""Safe extraction and cleanup of LLM JSON output."""

import json
import re
from typing import Any


class JSONRepair:
    """Safe extraction and structural repair of JSON from LLM output.
    
    Does NOT rewrite facts or guess missing values.
    """

    @classmethod
    def clean_and_parse(cls, raw_text: str) -> dict[str, Any]:
        """Extract and parse JSON object from LLM response text."""
        if not raw_text or not raw_text.strip():
            raise ValueError("Empty response from LLM.")

        text = raw_text.strip()

        # 1. Try markdown code block extraction
        code_block_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if code_block_match:
            candidate = code_block_match.group(1).strip()
        else:
            # 2. Try outermost brace extraction
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1 and end > start:
                candidate = text[start : end + 1].strip()
            else:
                candidate = text

        # 3. Direct JSON load attempt
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

        # 4. Safe structural fixes (remove trailing commas before closing braces/brackets)
        fixed = re.sub(r",\s*([\]}])", r"\1", candidate)

        try:
            return json.loads(fixed)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse LLM output as JSON: {e}") from e
