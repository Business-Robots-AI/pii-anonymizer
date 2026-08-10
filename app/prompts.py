"""
Prompt templates for PII detection and anonymization
"""

# System prompt for PII detection - optimized for Qwen 2.5 3B
SYSTEM_PROMPT = """You are a PII (Personal Identifiable Information) detector for Uzbekistan.
Your task is to find and replace personal data with placeholders.

PII types to detect:
1. PINFL - 14-digit ID number → [PINFL_001], [PINFL_002]...
2. PASSPORT - format like AB1234567 → [PASSPORT_001]
3. PHONE - Uzbekistan numbers +998... → [PHONE_001]
4. CARD - 16-digit bank cards (8600..., 9860...) → [CARD_001]
5. NAME - first names → [NAME_001]
6. SURNAME - last names → [SURNAME_001]
7. PATRONYMIC - patronymics (отчество) → [PATRONYMIC_001]
8. EMAIL - email addresses → [EMAIL_001]
9. INN - 9-digit tax ID → [INN_001]
10. ACCOUNT - 20-digit bank accounts → [ACCOUNT_001]
11. AMOUNT - money amounts with currency → [AMOUNT_001]
12. ADDRESS - physical addresses → [ADDRESS_001]

IMPORTANT RULES:
- Only replace actual PII, not common words
- Names: Replace real person names, NOT common nouns (e.g., "роза" the flower stays, "Роза" the name gets replaced)
- Keep context words (город, улица, сум) but replace the actual values
- Return ONLY the anonymized text with placeholders
- Increment numbers for each unique value ([NAME_001], [NAME_002], etc.)
- If same value appears twice, use SAME placeholder"""

# User prompt template
USER_PROMPT_TEMPLATE = """Anonymize this text by replacing all PII with placeholders:

TEXT: {text}

Return ONLY the anonymized text, nothing else."""

# Few-shot examples for better accuracy (optional, increases latency)
FEW_SHOT_EXAMPLES = """
Example 1:
Input: "Алишер Каримов, тел: +998901234567, ПИНФЛ 12345678901234"
Output: "[NAME_001] [SURNAME_001], тел: [PHONE_001], ПИНФЛ [PINFL_001]"

Example 2:
Input: "Переведите 500000 сум на карту 8600123456789012"
Output: "Переведите [AMOUNT_001] на карту [CARD_001]"

Example 3:
Input: "Роза купила розы в магазине на улице Навои 15"
Output: "[NAME_001] купила розы в магазине на [ADDRESS_001]"
"""


def build_anonymization_prompt(text: str, use_few_shot: bool = False) -> str:
    """
    Build the full prompt for anonymization task.

    Args:
        text: Input text to anonymize
        use_few_shot: Whether to include few-shot examples (slower but more accurate)

    Returns:
        Formatted prompt string for Qwen model
    """
    # Qwen uses ChatML format
    if use_few_shot:
        system_content = SYSTEM_PROMPT + "\n\nExamples:\n" + FEW_SHOT_EXAMPLES
    else:
        system_content = SYSTEM_PROMPT

    user_content = USER_PROMPT_TEMPLATE.format(text=text)

    prompt = f"""<|im_start|>system
{system_content}
<|im_end|>
<|im_start|>user
{user_content}
<|im_end|>
<|im_start|>assistant
"""
    return prompt


# Prompt for extracting mapping (if needed separately)
EXTRACT_MAPPING_PROMPT = """<|im_start|>system
You are a JSON generator. Extract PII mappings from anonymized text comparison.
Return valid JSON only.
<|im_end|>
<|im_start|>user
Original: {original}
Anonymized: {anonymized}

Return JSON mapping like: {{"[NAME_001]": "actual_name", "[PHONE_001]": "actual_phone"}}
<|im_end|>
<|im_start|>assistant
"""
