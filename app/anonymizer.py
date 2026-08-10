"""
PII Anonymizer Service - Core anonymization logic
"""
import re
import uuid
import logging
import time
from typing import Dict, Tuple, List, Optional
from collections import OrderedDict
from threading import Lock

from .llm_service import llm_service
from .prompts import build_anonymization_prompt
from .config import settings
from .names_db import (
    ALL_FIRST_NAMES, ALL_SURNAMES, NAME_CONTEXT_PATTERNS, has_name_suffix, looks_like_name,
    transliterate_name, extract_name_from_patronymic, fuzzy_match_name,
)

logger = logging.getLogger(__name__)

# Common Russian words that end with surname-like suffixes (-ов, -ова, -ев, -ин, etc.) but are NOT names
# Used to prevent false positives in name detection
NAME_STOP_WORDS = frozenset({
    # Genitive plural (-ов)
    'домов', 'столов', 'городов', 'годов', 'номеров', 'метров',
    'документов', 'клиентов', 'вопросов', 'ответов', 'центров',
    'офисов', 'банков', 'счетов', 'расходов', 'доходов', 'вкладов',
    'кредитов', 'долларов', 'процентов', 'филиалов', 'отделов',
    'продуктов', 'результатов', 'заказов', 'переводов',
    'специалистов', 'сотрудников', 'работников', 'магазинов',
    'вариантов', 'этажов', 'часов', 'призов', 'рублёв', 'рублев',
    'километров', 'килограммов', 'миллионов', 'миллиардов',
    'телефонов', 'паспортов', 'адресов', 'договоров',
    'стартапов', 'продуктов', 'сервисов', 'проектов',
    # Short adjectives / pronouns (-ов/-ова/-ев/-ева)
    'готов', 'готова', 'таков', 'такова', 'каков', 'какова',
    'здоров', 'здорова', 'нов', 'нова', 'суров', 'сурова',
    # Common nouns (-ова/-ева)
    'основа', 'голова', 'корова', 'подкова', 'обнова', 'молва',
    # Adverbs
    'снова', 'заново',
    # Common nouns (-ин/-ина)
    'магазин', 'бензин', 'витамин', 'аспирин', 'кофеин',
    'апельсин', 'дельфин', 'господин',
    'машина', 'картина', 'причина', 'длина', 'тишина', 'вершина',
    'половина', 'середина', 'витрина', 'дисциплина', 'медицина',
    'долина', 'витрина', 'корзина', 'паутина',
    # Common words ending in -ко/-енко
    'далеко', 'близко', 'легко', 'тяжело', 'высоко', 'низко',
    'молоко', 'яблоко', 'облако', 'зеркало',
    # Common verbs/words that might be adjacent
    'только', 'однако', 'немного', 'много',
    # Pronouns (Russian) — these were appearing as fake [NAME] because
    # they pattern-match capitalized standalone words.
    'я', 'ты', 'мы', 'вы', 'он', 'она', 'оно', 'они', 'вас', 'нас',
    'тебя', 'себя', 'меня', 'ему', 'ей', 'им', 'их', 'мой', 'твой',
    'наш', 'ваш', 'этот', 'тот', 'эта', 'та', 'эти', 'те',
    # Common Russian adjectives/verbs that get capitalized in marketing copy
    'безлимитный', 'безлимитная', 'безлимитное', 'неограниченный',
    'открой', 'откройте', 'получи', 'получите', 'используй', 'используйте',
    'развиваем', 'развивайте', 'попробуй', 'попробуйте',
    'запись', 'доступ', 'момент', 'моменты', 'социальное', 'социальная',
    'кремниевая', 'кремниевый', 'plain', 'unlimited', 'text', 'free', 'pro',
    # Single-character / 2-char tokens that should never be a name on their own
    'ai', 'ии', 'ам', 'ат', 'до', 'на', 'за', 'по', 'от', 'из',
})


class MappingCache:
    """Thread-safe cache for PII mappings with TTL"""

    def __init__(self, max_size: int = 10000, ttl: int = 3600):
        self._cache: OrderedDict[str, Tuple[Dict[str, str], float]] = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl
        self._lock = Lock()

    def store(self, mapping: Dict[str, str]) -> str:
        """Store mapping and return its ID"""
        mapping_id = str(uuid.uuid4())[:8]
        current_time = time.time()

        with self._lock:
            # Clean expired entries
            self._clean_expired(current_time)

            # Evict oldest if at capacity
            while len(self._cache) >= self._max_size:
                self._cache.popitem(last=False)

            self._cache[mapping_id] = (mapping, current_time)

        return mapping_id

    def get(self, mapping_id: str) -> Optional[Dict[str, str]]:
        """Retrieve mapping by ID"""
        with self._lock:
            if mapping_id not in self._cache:
                return None

            mapping, timestamp = self._cache[mapping_id]
            if time.time() - timestamp > self._ttl:
                del self._cache[mapping_id]
                return None

            return mapping

    def _clean_expired(self, current_time: float):
        """Remove expired entries"""
        expired = [
            k for k, (_, ts) in self._cache.items()
            if current_time - ts > self._ttl
        ]
        for k in expired:
            del self._cache[k]


class PIIAnonymizer:
    """
    PII Anonymization service using local LLM.

    Uses Qwen 2.5 3B for intelligent PII detection,
    with regex post-processing for structured data (PINFL, phones, etc.)
    """

    # Uzbekistan mobile operator codes (first 2 digits of 9-digit local number)
    UZ_OPERATOR_CODES = frozenset({
        '20',  # Perfectum Mobile
        '33',  # Humans
        '50',  # UMS
        '55',  # Humans
        '70',  # UzDigital
        '71',  # Tashkent landline
        '73',  # Beeline
        '74',  # Perfectum
        '75',  # UzDigital
        '77',  # Humans
        '78',  # Tashkent landline
        '88',  # UzMobile
        '90',  # Beeline
        '91',  # Beeline
        '93',  # Ucell
        '94',  # Ucell
        '95',  # UMS
        '97',  # UMS
        '98',  # UMS
        '99',  # UMS / Beeline
    })

    # Regex patterns for structured PII (used for validation and post-processing)
    PATTERNS = {
        "PINFL": r"\b\d{14}\b",
        "PASSPORT": (
            r"\b[Сс]ерия\s+[A-Za-z]{2}\s+(?:[Нн]омер\s+)?\d{7}\b"
            r"|\b[A-Za-z]{2}\s?\d{7}\b"
        ),
        "PHONE": (
            r"(?<!\d)\+?998[\s-]?\(?\d{2}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}(?!\d)"
            r"|(?<!\d)(?:\+7|8)[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}(?!\d)"
            r"|\b(?:20|33|50|55|70|71|73|74|75|77|78|88|90|91|93|94|95|97|98|99)\d{7}\b"
        ),
        # All card types - any 13-19 digits with optional spaces/dashes
        "CARD": r"\b\d(?:[\s-]?\d){12,18}\b",
        "INN": r"\b\d{9}\b",
        "ACCOUNT": r"\b\d{20}\b",
        "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        # Date of birth (DD.MM.YYYY, DD/MM/YYYY, DD-MM-YYYY) — years 1920-2025
        "DATE": r"\b(?:0[1-9]|[12]\d|3[01])[./-](?:0[1-9]|1[0-2])[./-](?:19[2-9]\d|200\d|201\d|202[0-5])\b",
    }

    # Address detection patterns (context-based, processed separately)
    ADDRESS_PATTERNS = [
        # ул. Name [NUM], кв NUM
        r'(?:ул\.?\s+[А-ЯЁа-яёA-Za-z][а-яёa-z]+(?:\s+\d+[а-яёa-z]?)?(?:\s*,?\s*(?:д\.?\s*\d+|кв\.?\s*\d+|корп\.?\s*\d+))*)',
        # улица Name [Name] [NUM]
        r'(?:улица\s+[А-ЯЁа-яёA-Za-z][а-яёa-z]+(?:\s+[А-ЯЁа-яёA-Za-z][а-яёa-z]+)?(?:\s+\d+)?)',
        # проспект/бульвар/переулок/шоссе/площадь Name
        r'(?:(?:проспект|бульвар|переулок|шоссе|площадь|набережная)\s+[А-ЯЁа-яёA-Za-z][а-яёa-z]+(?:\s+[А-ЯЁа-яёA-Za-z][а-яёa-z]+)?(?:\s+\d+)?)',
        # г. City or город City — restricted to a whitelist of real cities,
        # otherwise "г. Заберите" / "г шкафов" (the abbreviation followed
        # by any random capitalized word) would all become fake addresses.
        r'(?:(?:г\.|город)\s+(?:Ташкент|Самарканд|Бухара|Хива|Наманган|Андижан|Фергана|Карши|Нукус|Термез|Ургенч|Москва|Санкт-Петербург|Екатеринбург|Новосибирск|Казань|Алматы|Астана|Бишкек|Душанбе|Ашхабад|Баку|Минск|Киев|Варшава|Стамбул|Дубай))',
        # Uzbek: Name ko'chasi [NUM-uy]
        r"(?:[A-Za-zА-ЯЁа-яё]+\s+ko'?chasi?\s*(?:\d+[\s-]*uy)?)",
        # Uzbek: City shahri / tumani / viloyati
        r'(?:[A-ZА-ЯЁ][a-zа-яё]+\s+(?:shahri?|tumani?|viloyati?))',
    ]

    def __init__(self):
        self.mapping_cache = MappingCache(
            max_size=settings.max_cache_size,
            ttl=settings.mapping_ttl
        )
        self._last_confidence = {}  # placeholder → {confidence, method}

    def anonymize(self, text: str, use_few_shot: bool = False, use_llm: Optional[bool] = None,
                  seed_values: Optional[Dict[str, List[str]]] = None) -> Tuple[str, Dict[str, str], List[str], int]:
        """
        Anonymize text by replacing PII with placeholders.

        Args:
            text: Input text to anonymize
            use_few_shot: Use few-shot examples (slower but more accurate)
            use_llm: Override settings.use_llm (None = use setting)
            seed_values: Force-anonymize these tokens BEFORE regex/dictionary,
                regardless of detector coverage. Shape:
                  {"NAME": ["Amar", "Farkhadi"], "PHONE": ["+998901234567"], ...}
                Used by the backend to inject Contact.firstName / lastName /
                phone / email so non-dictionary surnames still get redacted.

        Returns:
            Tuple of (anonymized_text, mapping, pii_types_found, processing_time_ms)
        """
        should_use_llm = use_llm if use_llm is not None else settings.use_llm

        if not should_use_llm:
            return self._anonymize_regex_only(text, seed_values=seed_values)

        return self._anonymize_with_llm(text, use_few_shot, seed_values=seed_values)

    def _apply_seed_values(self, text: str, seed_values: Optional[Dict[str, List[str]]],
                           mapping: Dict[str, str], counters: Dict[str, int],
                           confidence: Dict[str, dict], pii_types_found: set) -> str:
        """
        Pre-replace known tokens with placeholders BEFORE the regex/dictionary
        pass. Each token gets a fresh [TYPE_NNN] placeholder. Longer tokens go
        first so "Amar Farkhadi" wins over "Amar" alone — otherwise the longer
        match would be missed once "Amar" is already replaced.

        Skips empty strings, whitespace-only values, and tokens already in
        mapping.values() so we don't double-allocate placeholders for the
        same person mentioned twice in seed values.
        """
        if not seed_values:
            return text
        # Flatten + sort by descending length so multi-word names win first.
        flat: List[Tuple[str, str]] = []
        for pii_type, values in seed_values.items():
            if not isinstance(values, list):
                continue
            for v in values:
                if not isinstance(v, str):
                    continue
                v_clean = v.strip()
                if len(v_clean) < 2:
                    continue
                flat.append((pii_type.upper(), v_clean))
        flat.sort(key=lambda x: -len(x[1]))

        result = text
        for pii_type, value in flat:
            if value in mapping.values():
                continue  # already mapped
            # Case-insensitive word-boundary match. \b doesn't always work for
            # Cyrillic in Python re; use a lookahead/lookbehind that excludes
            # letters and digits explicitly so we don't break inside words.
            # We also catch the exact-case path first for speed.
            try:
                # Escape regex meta-chars in the value (e.g. + in phone numbers).
                escaped = re.escape(value)
                pattern = re.compile(
                    rf'(?<![\wЀ-ӿԀ-ԯ]){escaped}(?![\wЀ-ӿԀ-ԯ])',
                    flags=re.IGNORECASE
                )
                if not pattern.search(result):
                    continue
                counters[pii_type] = counters.get(pii_type, 0) + 1
                placeholder = f"[{pii_type}_{counters[pii_type]:03d}]"
                result = pattern.sub(placeholder, result)
                mapping[placeholder] = value
                confidence[placeholder] = {"confidence": "high", "method": "seed"}
                pii_types_found.add(pii_type)
            except re.error:
                continue
        return result

    def _anonymize_regex_only(self, text: str, seed_values: Optional[Dict[str, List[str]]] = None
                              ) -> Tuple[str, Dict[str, str], List[str], int]:
        """Fast anonymization using regex patterns + name database (~5ms)."""
        start_time = time.time()
        result = text
        mapping = {}
        counters = {}
        confidence = {}  # placeholder → {confidence, method}
        pii_types_found_set: set = set()

        # Seed pass — known tokens replaced FIRST. Counters increment naturally
        # so the downstream regex/dictionary passes continue from this point.
        if seed_values:
            result = self._apply_seed_values(result, seed_values, mapping, counters,
                                             confidence, pii_types_found_set)

        # ======== STRUCTURED PII (regex patterns) ========
        for pii_type, pattern in self.PATTERNS.items():
            matches = list(set(re.findall(pattern, text)))
            for match in matches:
                if match not in mapping.values():
                    actual_type = pii_type
                    # 9-digit number starting with UZ operator code → PHONE, not INN
                    if pii_type == "INN" and len(match) == 9 and match[:2] in self.UZ_OPERATOR_CODES:
                        actual_type = "PHONE"
                    counters[actual_type] = counters.get(actual_type, 0) + 1
                    placeholder = f"[{actual_type}_{counters[actual_type]:03d}]"
                    result = result.replace(match, placeholder)
                    mapping[placeholder] = match
                    confidence[placeholder] = {"confidence": "high", "method": "regex"}

        # ======== ADDRESS DETECTION (context-based) ========
        for addr_pat in self.ADDRESS_PATTERNS:
            for match in re.finditer(addr_pat, result, re.IGNORECASE):
                addr = match.group(0)
                if addr not in mapping.values() and '[' not in addr:
                    counters["ADDRESS"] = counters.get("ADDRESS", 0) + 1
                    placeholder = f"[ADDRESS_{counters['ADDRESS']:03d}]"
                    result = result.replace(addr, placeholder, 1)
                    mapping[placeholder] = addr
                    confidence[placeholder] = {"confidence": "medium", "method": "address_context"}

        # ======== PATRONYMIC → NAME INFERENCE (pre-step) ========
        dynamic_names = set()
        patr_pattern = r'\b([А-ЯЁа-яёA-Za-z]{5,}(?:ович|евич|овна|евна|ич|ична|ovich|evich|ovna|evna))\b'
        for m in re.finditer(patr_pattern, text, re.IGNORECASE):
            base = extract_name_from_patronymic(m.group(1))
            if base and len(base) >= 3:
                dynamic_names.add(base)

        # ======== HELPERS ========
        def _is_patronymic(w):
            wl = w.lower()
            return bool(re.match(r'^[а-яёa-z]{3,}$', wl, re.IGNORECASE)) and any(
                wl.endswith(s) for s in ('ович', 'евич', 'ич', 'овна', 'евна', 'ична',
                                          'ovich', 'evich', 'ich', 'ovna', 'evna',
                                          'угли', 'ўғли', 'ugli', 'кизи', 'қизи', 'qizi'))

        def _is_surname_like(w):
            wl = w.lower()
            if wl in NAME_STOP_WORDS:
                return False
            if w in ALL_SURNAMES or w.capitalize() in ALL_SURNAMES:
                return True
            # Suffix-only heuristic was way too greedy (matched "Кремниевая",
            # "вашего", any -ая adjective) and produced massive false-positive
            # streams in marketing copy. Restrict it to the most distinctive
            # surname suffixes only — the ones that almost never appear as
            # ordinary words. Generic Russian adjective endings (-ая, -ый, -ий)
            # were the main culprits and are now removed.
            return len(wl) >= 4 and any(
                wl.endswith(s) for s in ('ский', 'ская', 'цкий', 'цкая',
                                          'енко', 'янц',
                                          'skiy', 'skaya'))

        def _is_known_name(w):
            # Check DB directly
            if w in ALL_FIRST_NAMES or w.capitalize() in ALL_FIRST_NAMES or w.title() in ALL_FIRST_NAMES:
                return True
            # Check patronymic-inferred names
            if w.capitalize() in dynamic_names:
                return True
            # Check transliterated version
            translit = transliterate_name(w)
            if translit and (translit in ALL_FIRST_NAMES or translit.capitalize() in ALL_FIRST_NAMES or translit.title() in ALL_FIRST_NAMES):
                return True
            return False

        def _replace_name(text, full_name, method="name_combo"):
            if full_name in text and full_name not in mapping.values():
                counters["NAME"] = counters.get("NAME", 0) + 1
                placeholder = f"[NAME_{counters['NAME']:03d}]"
                text = text.replace(full_name, placeholder)
                mapping[placeholder] = full_name
                conf = "high" if method in ("db_name", "name_combo") else "medium"
                confidence[placeholder] = {"confidence": conf, "method": method}
            return text

        # ======== Step 1: 3-word full names (Фамилия Имя Отчество) ========
        name3_pattern = r"\b([А-ЯЁа-яёA-Za-z][а-яёa-z]+)\s+([А-ЯЁа-яёA-Za-z][а-яёa-z]+)\s+([А-ЯЁа-яёA-Za-z][а-яёa-z]+)\b"
        for m in re.finditer(name3_pattern, result):
            w1, w2, w3 = m.group(1), m.group(2), m.group(3)
            if (_is_surname_like(w1) or _is_known_name(w1)) and _is_patronymic(w3):
                result = _replace_name(result, f"{w1} {w2} {w3}", "name_combo")
            elif _is_known_name(w1) and _is_known_name(w2) and _is_patronymic(w3):
                result = _replace_name(result, f"{w1} {w2} {w3}", "name_combo")

        # ======== Step 2: 2-word name combos ========
        name2_pattern = r"\b([А-ЯЁа-яёA-Za-z][а-яёa-z]{2,})\s+([А-ЯЁа-яёA-Za-z][а-яёa-z]{2,})\b"
        for m in re.finditer(name2_pattern, result):
            w1, w2 = m.group(1), m.group(2)
            full = f"{w1} {w2}"
            if full in mapping.values() or any(full in v for v in mapping.values()):
                continue
            if '[' in w1 or '[' in w2:
                continue
            if (_is_known_name(w1) or _is_surname_like(w1)) and _is_patronymic(w2):
                result = _replace_name(result, full, "name_combo")
            elif _is_surname_like(w1) and _is_known_name(w2):
                result = _replace_name(result, full, "name_combo")
            elif _is_known_name(w1) and _is_surname_like(w2):
                result = _replace_name(result, full, "name_combo")
            elif _is_known_name(w1) and _is_known_name(w2):
                result = _replace_name(result, full, "name_combo")
            # NOTE: a "suffix-only" 2-word heuristic used to live here that
            # matched anything like "Кремниевая долина" / "Безлимитный доступ"
            # because long lists of -ов/-ев/-ин endings collide with ordinary
            # Russian words. It was the dominant source of false positives
            # in real chat traffic, so it has been removed. To catch a real
            # name now, at least one half must be in our names DB.

        # ======== Step 3: Standalone names from database ========
        # Skip 1-3 char DB entries (e.g. "Ai", "Ам") — too many collisions
        # with ordinary words and abbreviations to trust on their own.
        for name in ALL_FIRST_NAMES:
            if len(name) < 4:
                continue
            pattern = r'\b' + re.escape(name) + r'\b'
            if re.search(pattern, result, re.IGNORECASE):
                match = re.search(pattern, result, re.IGNORECASE)
                if match and match.group() not in mapping.values() and not any(match.group() in v for v in mapping.values()):
                    matched_token = match.group()
                    if matched_token.lower() in NAME_STOP_WORDS:
                        continue
                    counters["NAME"] = counters.get("NAME", 0) + 1
                    placeholder = f"[NAME_{counters['NAME']:03d}]"
                    result = re.sub(pattern, placeholder, result, flags=re.IGNORECASE)
                    mapping[placeholder] = matched_token
                    confidence[placeholder] = {"confidence": "high", "method": "db_name"}

        # ======== Step 4: Standalone surnames from database ========
        for surname in ALL_SURNAMES:
            if len(surname) < 4:
                continue
            pattern = r'\b' + re.escape(surname) + r'\b'
            if re.search(pattern, result, re.IGNORECASE):
                match = re.search(pattern, result, re.IGNORECASE)
                if match and match.group() not in mapping.values() and not any(match.group() in v for v in mapping.values()):
                    matched_token = match.group()
                    if matched_token.lower() in NAME_STOP_WORDS:
                        continue
                    counters["NAME"] = counters.get("NAME", 0) + 1
                    placeholder = f"[NAME_{counters['NAME']:03d}]"
                    result = re.sub(pattern, placeholder, result, flags=re.IGNORECASE)
                    mapping[placeholder] = matched_token
                    confidence[placeholder] = {"confidence": "high", "method": "db_name"}

        # ======== Step 5: Context-based name detection ========
        # Patterns are case-insensitive in the captured group too — users
        # routinely type names lowercase ("меня зовут алишер"), and a
        # capital-only regex would silently leak those names to the LLM.
        context_patterns = [
            r'(?:меня\s+зовут|зовут\s+меня|моё?\s+имя|я\s+[-–—]?\s*)\s+([А-ЯЁA-Zа-яёa-z]+(?:\s+[А-ЯЁA-Zа-яёa-z]+)?)',
            r'(?:клиент[ка]?|гражданин[ка]?|господин|госпожа)\s+([А-ЯЁA-Zа-яёa-z]+(?:\s+[А-ЯЁA-Zа-яёa-z]+)?)',
            r'(?:mening\s+ismim|ismim|men)\s+([A-Za-z]+(?:\s+[A-Za-z]+)?)',
            r'(?:mijoz|fuqaro|janob|xonim)\s+([A-Za-z]+(?:\s+[A-Za-z]+)?)',
        ]
        for ctx_pattern in context_patterns:
            for match in re.finditer(ctx_pattern, result, re.IGNORECASE):
                name = match.group(1)
                if name not in mapping.values() and not any(name in v for v in mapping.values()):
                    if '[' not in name:
                        counters["NAME"] = counters.get("NAME", 0) + 1
                        placeholder = f"[NAME_{counters['NAME']:03d}]"
                        result = result[:match.start(1)] + placeholder + result[match.end(1):]
                        mapping[placeholder] = name
                        confidence[placeholder] = {"confidence": "medium", "method": "context"}

        # ======== Step 6: Suffix-based compound names ========
        suffix_pattern = r'\b([А-ЯЁA-Z][а-яёa-z]{5,})\b'
        for match in re.finditer(suffix_pattern, result):
            word = match.group(1)
            if word not in mapping.values() and not any(word in v for v in mapping.values()) and has_name_suffix(word):
                if '[' not in word:
                    counters["NAME"] = counters.get("NAME", 0) + 1
                    placeholder = f"[NAME_{counters['NAME']:03d}]"
                    result = result.replace(word, placeholder, 1)
                    mapping[placeholder] = word
                    confidence[placeholder] = {"confidence": "medium", "method": "compound_suffix"}

        # ======== Step 7: Fuzzy name matching (typos) ========
        fuzzy_word_pattern = r'\b([А-ЯЁA-Z][а-яёa-z]{2,})\b'
        for match in re.finditer(fuzzy_word_pattern, result):
            word = match.group(1)
            if word in mapping.values() or any(word in v for v in mapping.values()):
                continue
            if '[' in word or word.lower() in NAME_STOP_WORDS:
                continue
            # Skip if already a known name (would've been caught earlier)
            if word in ALL_FIRST_NAMES or word.capitalize() in ALL_FIRST_NAMES:
                continue
            fuzzy_result = fuzzy_match_name(word)
            if fuzzy_result:
                counters["NAME"] = counters.get("NAME", 0) + 1
                placeholder = f"[NAME_{counters['NAME']:03d}]"
                result = result.replace(word, placeholder)
                mapping[placeholder] = word
                confidence[placeholder] = {"confidence": "low", "method": "fuzzy", "matched_to": fuzzy_result}

        # Store confidence for external access
        self._last_confidence = confidence

        pii_types = self._get_pii_types(mapping)
        processing_time_ms = int((time.time() - start_time) * 1000)

        logger.info(
            f"Regex+Names: {len(text)} chars -> {len(result)} chars, "
            f"found {len(mapping)} PII items in {processing_time_ms}ms"
        )

        return result, mapping, pii_types, processing_time_ms

    def _anonymize_with_llm(self, text: str, use_few_shot: bool = False,
                            seed_values: Optional[Dict[str, List[str]]] = None
                            ) -> Tuple[str, Dict[str, str], List[str], int]:
        """Full anonymization using LLM + regex post-processing (slow)."""
        start_time = time.time()

        # Seed pass — pre-replace caller-supplied known tokens FIRST so the
        # LLM (and later regex) never sees real Contact data. Counters and
        # mapping start with whatever the seed produced; subsequent passes
        # add on top.
        mapping: Dict[str, str] = {}
        counters: Dict[str, int] = {}
        confidence: Dict[str, dict] = {}
        pii_types_found_set: set = set()
        if seed_values:
            text = self._apply_seed_values(text, seed_values, mapping, counters,
                                           confidence, pii_types_found_set)

        prompt = build_anonymization_prompt(text, use_few_shot=use_few_shot)

        anonymized_text, metadata = llm_service.generate(
            prompt,
            max_tokens=len(text) + 200,
        )

        llm_mapping = self._extract_mapping(text, anonymized_text)
        # Merge LLM-discovered mapping on top of the seed mapping. Seed
        # placeholders already in `mapping` won't get overridden because
        # llm_mapping uses different placeholder indices.
        mapping.update(llm_mapping)

        anonymized_text, additional_mapping = self._regex_post_process(
            anonymized_text, text, mapping
        )
        mapping.update(additional_mapping)

        pii_types = self._get_pii_types(mapping)

        processing_time_ms = int((time.time() - start_time) * 1000)

        logger.info(
            f"LLM: {len(text)} chars -> {len(anonymized_text)} chars, "
            f"found {len(mapping)} PII items in {processing_time_ms}ms"
        )

        return anonymized_text, mapping, pii_types, processing_time_ms

    def _extract_mapping(self, original: str, anonymized: str) -> Dict[str, str]:
        """
        Extract mapping of placeholders to original values.

        Uses pattern matching to find placeholder -> original value pairs.
        """
        mapping = {}

        # Find all placeholders in anonymized text
        placeholder_pattern = r"\[([A-Z]+)_(\d+)\]"
        placeholders = re.findall(placeholder_pattern, anonymized)

        if not placeholders:
            return mapping

        # For each placeholder, try to find corresponding value in original
        # This is a simplified approach - in production, use more sophisticated alignment
        for pii_type, num in placeholders:
            placeholder = f"[{pii_type}_{num}]"
            if placeholder in mapping:
                continue

            # Try to find the value using regex patterns if available
            if pii_type in self.PATTERNS:
                matches = re.findall(self.PATTERNS[pii_type], original)
                idx = int(num) - 1
                if 0 <= idx < len(matches):
                    mapping[placeholder] = matches[idx]

        return mapping

    def _regex_post_process(
        self,
        anonymized: str,
        original: str,
        existing_mapping: Dict[str, str]
    ) -> Tuple[str, Dict[str, str]]:
        """
        Post-process to catch any PII missed by LLM using regex patterns.

        Only processes structured data (PINFL, phones, cards, etc.)
        """
        additional_mapping = {}
        result = anonymized

        # Get values already in mapping
        mapped_values = set(existing_mapping.values())

        for pii_type, pattern in self.PATTERNS.items():
            # Find all matches in ORIGINAL that weren't caught
            original_matches = set(re.findall(pattern, original))

            # Check which ones are still in anonymized text (weren't replaced)
            for match in original_matches:
                if match in mapped_values:
                    continue

                # Normalize match (remove spaces for comparison)
                normalized_match = match.replace(" ", "")

                # Check if this value appears in the anonymized text
                if match in result or normalized_match in result:
                    # Find next available number for this type
                    existing_nums = [
                        int(re.search(r"_(\d+)\]", k).group(1))
                        for k in existing_mapping
                        if k.startswith(f"[{pii_type}_")
                    ] or [0]
                    next_num = max(existing_nums) + 1

                    placeholder = f"[{pii_type}_{next_num:03d}]"

                    # Replace in result
                    result = result.replace(match, placeholder)
                    result = result.replace(normalized_match, placeholder)
                    additional_mapping[placeholder] = match

        return result, additional_mapping

    def _get_pii_types(self, mapping: Dict[str, str]) -> List[str]:
        """Extract unique PII types from mapping"""
        types = set()
        for placeholder in mapping.keys():
            match = re.match(r"\[([A-Z]+)_\d+\]", placeholder)
            if match:
                types.add(match.group(1))
        return sorted(list(types))

    def deanonymize(self, text: str, mapping: Dict[str, str]) -> str:
        """
        Restore original PII from anonymized text.

        Args:
            text: Anonymized text with placeholders
            mapping: Dictionary mapping placeholders to original values

        Returns:
            Text with original PII restored
        """
        result = text
        for placeholder, original_value in mapping.items():
            result = result.replace(placeholder, original_value)
        return result

    def store_mapping(self, mapping: Dict[str, str]) -> str:
        """Store mapping in cache and return ID"""
        return self.mapping_cache.store(mapping)

    def get_mapping(self, mapping_id: str) -> Optional[Dict[str, str]]:
        """Retrieve mapping from cache"""
        return self.mapping_cache.get(mapping_id)


# Global instance
anonymizer = PIIAnonymizer()
