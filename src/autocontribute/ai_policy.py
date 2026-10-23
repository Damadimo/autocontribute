"""Repository AI-contribution policies: a deterministic reading and checks on model readings."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field

from autocontribute.domain import DomainModel

AiPolicyStance = Literal["ban", "conditional", "permissive", "none", "unclear"]
# Files written for coding agents; their rules bind an agent even when they never say "AI".
AGENT_INSTRUCTION_FILES = frozenset(
    {"agents.md", "claude.md", "gemini.md", "copilot-instructions.md"}
)


@dataclass(frozen=True, slots=True)
class PolicyFile:
    """One policy file read at a pinned ref, as raw text with any HTML comments."""

    repository: str
    path: str
    text: str


class AiPolicyQuote(DomainModel):
    """A verbatim passage of one policy file."""

    repository: str
    path: str
    text: str


class RepositoryAiPolicy(DomainModel):
    """What a repository's policy files say about contributions made with AI.

    ``unclear`` means a model claimed a ban that its quotes could not support.
    """

    stance: AiPolicyStance
    requires_disclosure: bool = False
    disclosure_requirements: list[str] = Field(default_factory=list)
    requires_human_written_text: bool = False
    quotes: list[AiPolicyQuote] = Field(default_factory=list)


_MAX_QUOTES = 10
_MAX_QUOTE_CHARACTERS = 500
_DIGEST_DOMAIN = b"autocontribute.ai-policy-files.v1\x00"
# Emphasis marks, zero-width characters and curly apostrophes are blanked or straightened in a
# copy of the same length, so that matches on the copy map back to verbatim quotes.
_MASKED_CHARACTERS = re.compile("[*_`~\u200b-\u200d\u2060\ufeff]")
_STRAIGHT_QUOTES = str.maketrans({"\u2018": "'", "\u2019": "'"})
_SENTENCE_BREAK = re.compile(
    r"(?<=[.!?])\s+|\n[ \t]*\n|\n(?=[ \t]*(?:[-+*]|\d+[.)])[ \t])|\n(?=[ \t]*#)"
    r"|\n[ \t]*[=\-~^]{3,}[ \t]*(?=\n|$)|<!--|-->|\|"
)
_CLAUSE_BREAK = re.compile(r";|\b(?:but|however|although|though|whereas)\b", re.I)
_NAMED_TOOL = r"(?:copilot|chatgpt|claude|codex|gemini|openclaw)"
_MODEL = rf"(?:ai|llms?|large\s+language\s+models?|generative\s+ai|gen-?ai|{_NAMED_TOOL})"
_UNATTENDED_TOOL = (
    r"(?:agentic"
    r"|(?:autonomous|unsupervised|unattended)\s+(?:(?:ai|llm|coding)\s+)?(?:agents?|tools?|bots?)"
    r"|fully[\s-]+automated)"
)
_BAN_SUBJECT = re.compile(
    rf"\b(?:{_UNATTENDED_TOOL}"
    r"|(?:ai|llm|coding)\s+agents?"
    r"|(?:ai|llm)\s+(?:content\s+|code\s+)?generators?"
    rf"|(?:ai|llm|machine|bot|{_NAMED_TOOL})[\s-]+(?:generated|written|authored|created|assisted)"
    r"|(?:generated|written|authored|created|produced|made)\s+(?:\w+\s+)?(?:by|with|using|via)"
    rf"\s+(?:an?\s+|the\s+)?(?:{_MODEL}|agents?))\b",
    re.I,
)
_BAN_PREDICATE = re.compile(
    r"\b(?:(?:not|never)\s+(?:be\s+)?accept(?:ed|ing)?"
    r"|(?:won't|wont|don't|doesn't|cannot|can't)\s+(?:be\s+)?accept(?:ed)?"
    r"|no\s+longer\s+(?:be\s+)?accept(?:ed|ing)?"
    r"|(?:will|may|shall|would|are|is)\s+(?:be\s+)?(?:closed|rejected)"
    r"|(?:do|does|will)\s+not\s+allow|(?:don't|doesn't|won't)\s+allow"
    r"|not\s+(?:be\s+)?allowed|disallowed"
    r"|prohibit(?:ed|s)?|forbid(?:den|s)?|refrain\s+from|ban(?:s|ned)?"
    r"|must\s+be\s+(?:opened|submitted|written|authored|created|made)\s+by\s+(?:a\s+)?humans?"
    r"|declin(?:e|ed|es|ing)|reject(?:ed|s)?)\b",
    re.I,
)
# "No unsupervised agentic tools" bans by naming the tool after "no". Disclosure checkboxes
# such as "No AI-generated code" use the same form for AI output, so only unattended tools count.
_NO_SUBJECT = re.compile(rf"\bno\s+(?:[\w-]+\s+){{0,2}}?{_UNATTENDED_TOOL}\b", re.I)
_CONTRIBUTION_TERM = re.compile(
    r"\b(?:contribut\w*|pull[\s-]+requests?|prs?|merge[\s-]+requests?|patch(?:es)?"
    r"|submissions?|submit\w*|code|coding)\b",
    re.I,
)
# Every sentence of these files is about contributing, so a ban there needs no context word.
_CONTRIBUTION_FILE = re.compile(
    r"contribut(?!ors\b).*|pull_request_template.*|.*ai.*polic.*|.*llm.*polic.*"
    r"|ai[-_]contribution.*"
)
_AI_TERM = re.compile(
    r"\b(?:(?-i:AI)|LLMs?|large\s+language\s+models?|generative|gen-?ai|chatgpt|copilot|claude"
    r"|codex|gemini|agentic|(?:ai|coding|autonomous)\s+agents?|bot[\s-]+authored"
    r"|machine[\s-]+generated|vibe[\s-]+cod\w*)\b",
    re.I,
)
_DISCLOSURE = re.compile(r"\b(?:disclos\w*|assisted-by|generated-by)\b", re.I)
_TRAILER = re.compile(r"\b(?:assisted-by|generated-by)\b", re.I)
_HUMAN_TEXT_RULE = re.compile(
    r"\b(?:(?P<own>own\s+words)"
    r"|(?:do\s+not|don't|must\s+not|mustn't|should\s+not|shouldn't|never|cannot|can't|may\s+not)"
    r"\s+use\s+[^.;]{0,40}?\bto\s+(?:\w+\s+){0,2}?"
    r"(?:write|generate|draft|compose|speak|communicate|respond|reply|answer|translate"
    r"|summari[sz]e)"
    r"|(?:written|authored|composed)\s+by\s+(?:a\s+)?(?:human|you|yourself)"
    r"|human[\s-]+written)\b",
    re.I,
)
_TEXT_OBJECT = re.compile(
    r"\b(?:descriptions?|comments?|messages?|replies|responses?|communicat\w*|discussions?"
    r"|text|prose|for\s+you|reviews?|titles?)\b",
    re.I,
)


def deterministic_ai_policy(files: Sequence[PolicyFile]) -> RepositoryAiPolicy:
    """Read bans, disclosure rules and human-written-text rules sentence by sentence.

    A ban needs a subject (agentic or autonomous tools, AI-generated work) and a predicate (not
    accepted, will be closed, prohibited, ...) in one clause of a sentence about contributing.
    """

    bans: list[AiPolicyQuote] = []
    disclosures: list[AiPolicyQuote] = []
    human_text: list[AiPolicyQuote] = []
    for file in files:
        contribution_file = bool(
            _CONTRIBUTION_FILE.fullmatch(PurePosixPath(file.path.casefold()).name)
        )
        for quote, sentence in _sentences(file):
            if _states_ban(sentence, contribution_file=contribution_file):
                bans.append(quote)
            if _TRAILER.search(sentence) or (
                _DISCLOSURE.search(sentence) and _AI_TERM.search(sentence)
            ):
                disclosures.append(quote)
            if _requires_human_text(sentence):
                human_text.append(quote)
    conditions = list(
        {
            (quote.repository, quote.path, quote.text): quote
            for quote in [*disclosures, *human_text]
        }.values()
    )
    if bans:
        stance: AiPolicyStance = "ban"
        quotes = bans
    elif conditions:
        stance = "conditional"
        quotes = conditions
    else:
        return RepositoryAiPolicy(stance="none")
    return RepositoryAiPolicy(
        stance=stance,
        requires_disclosure=bool(disclosures),
        disclosure_requirements=[quote.text for quote in disclosures[:_MAX_QUOTES]],
        requires_human_written_text=bool(human_text),
        quotes=quotes[:_MAX_QUOTES],
    )


def ai_policy_files(files: Sequence[PolicyFile]) -> list[PolicyFile]:
    """Keep the files a classifier needs: those that mention AI, and agent instruction files."""

    return [
        file
        for file in files
        if _AI_TERM.search(file.text)
        or PurePosixPath(file.path.casefold()).name in AGENT_INSTRUCTION_FILES
    ]


def ai_policy_digest(files: Sequence[PolicyFile]) -> str:
    """Identify a set of policy files, so a reading of them can be reused until one changes."""

    payload = sorted([file.repository.casefold(), file.path, file.text] for file in files)
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(_DIGEST_DOMAIN + encoded).hexdigest()


def checked_ai_policy(
    claimed: RepositoryAiPolicy,
    files: Sequence[PolicyFile],
    *,
    fallback: RepositoryAiPolicy,
) -> RepositoryAiPolicy:
    """Keep a model's reading only when every quote appears verbatim in the file it names.

    A ban or unclear reading that fails the check becomes unclear, so the repository is skipped
    rather than trusted; any other failing reading gives way to ``fallback``.
    """

    texts = {(file.repository.casefold(), file.path): _collapsed(file.text) for file in files}
    verified = [
        quote
        for quote in claimed.quotes
        if _collapsed(quote.text)
        and _collapsed(quote.text) in texts.get((quote.repository.casefold(), quote.path), "")
    ]
    evidenced = bool(verified) or claimed.stance in {"permissive", "none"}
    if len(verified) == len(claimed.quotes) and evidenced:
        return claimed
    if claimed.stance in {"ban", "unclear"}:
        return RepositoryAiPolicy(stance="unclear", quotes=verified)
    return fallback


def _sentences(file: PolicyFile) -> Iterator[tuple[AiPolicyQuote, str]]:
    """Yield each sentence as a verbatim quote and as the copy that patterns match."""

    matchable = _MASKED_CHARACTERS.sub(" ", file.text).translate(_STRAIGHT_QUOTES)
    start = 0
    for boundary in (*_SENTENCE_BREAK.finditer(file.text), None):
        end = len(file.text) if boundary is None else boundary.start()
        raw = file.text[start:end]
        text = raw.strip()
        if text:
            offset = start + raw.index(text)
            yield (
                AiPolicyQuote(
                    repository=file.repository,
                    path=file.path,
                    text=text[:_MAX_QUOTE_CHARACTERS],
                ),
                matchable[offset : offset + len(text)],
            )
        if boundary is not None:
            start = boundary.end()


def _states_ban(sentence: str, *, contribution_file: bool) -> bool:
    if not (contribution_file or _CONTRIBUTION_TERM.search(sentence)):
        return False
    return any(
        (_BAN_SUBJECT.search(clause) and _BAN_PREDICATE.search(clause))
        or _NO_SUBJECT.search(clause)
        for clause in _CLAUSE_BREAK.split(sentence)
    )


def _requires_human_text(sentence: str) -> bool:
    rule = _HUMAN_TEXT_RULE.search(sentence)
    return (
        rule is not None
        and _AI_TERM.search(sentence) is not None
        and (rule.group("own") is not None or _TEXT_OBJECT.search(sentence) is not None)
    )


def _collapsed(text: str) -> str:
    return " ".join(text.split())


__all__ = [
    "AGENT_INSTRUCTION_FILES",
    "AiPolicyQuote",
    "AiPolicyStance",
    "PolicyFile",
    "RepositoryAiPolicy",
    "ai_policy_digest",
    "ai_policy_files",
    "checked_ai_policy",
    "deterministic_ai_policy",
]
