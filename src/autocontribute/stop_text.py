"""Maintainer text that turns away automated or AI contributions.

Discovery reads it in issue discussions and lifecycle sync in pull-request comments; one pattern
keeps both readers in agreement about the same sentence.
"""

from __future__ import annotations

import re
from typing import Final

_AUTOMATION = (
    r"(?:(?:ai|llm|agent|machine|bot|model)[\s-]+"
    r"(?:generated|assisted|written|authored|made|created|driven)"
    r"|(?:ai|llm|coding)\s+agents?|agentic|automat(?:ed|ion)|ai|llms?|bots?|agents?)"
)
_SUBMISSIONS = (
    r"(?:pull\s+requests?|prs?|contributions?|submissions?|patch(?:es)?|changes|code|work)"
)
# The automation term must qualify what is submitted: "stop the bot from reformatting files" and
# "don't open the agents module" name automation without turning anyone away.
_TARGET = (
    rf"(?:{_AUTOMATION}[\s-]+(?:[\w-]+\s+)?{_SUBMISSIONS}"
    rf"|{_SUBMISSIONS}\s+(?:(?:generated|written|authored|made|created|opened|submitted|sent)\s+)?"
    rf"(?:from|by|with|using|via)\s+(?:an?\s+|the\s+|any\s+)?{_AUTOMATION})"
)
_DETERMINERS = r"(?:(?:a|all|an|any|further|more|new|such|the|them|these|this|those|us|your)\s+)*"
# A rule about how automated work must be sent ("do not send automated PRs more than once a
# day") continues past its object; a refusal ends there or names only where it applies.
_TAIL = (
    r"(?=\s*(?:[.!?;:,)\u2013\u2014\n]|$)"
    r"|\s+(?:here|anymore|any\s+more|again|at\s+all|for\s+now|right\s+now|at\s+this\s+time"
    r"|(?:to|in|into|for|on)\s+(?:this|the|our)\s+(?:repo|repository|project|codebase|issue)"
    r"|please|until|because|since|as)\b)"
)
_SUBMIT = (
    r"(?:open(?:ing)?|send(?:ing)?|submit(?:ting)?|creat(?:e|ing)|fil(?:e|ing)|mak(?:e|ing)"
    r"|continu(?:e|ing)\s+with)"
)
_DIRECTIVE = r"(?:stop|cease|quit|do\s+not|don't|never|no\s+more)"

AUTOMATION_STOP: Final = re.compile(
    r"(?:"
    # "Stop opening AI-generated PRs", "Stop this PR and all automated work"
    rf"\b{_DIRECTIVE}\s+(?:{_SUBMIT}\s+|(?:this|your)\s+(?:pull\s+request|pr)\s+and\s+)?"
    rf"{_DETERMINERS}{_TARGET}{_TAIL}"
    # "Please stop using bots to open pull requests"
    rf"|\b{_DIRECTIVE}\s+us(?:e|ing)\s+{_DETERMINERS}{_AUTOMATION}\s+(?:to|for)\s+"
    rf"(?:open|send|submit|creat|fil|writ|generat|mak)\w*\s+{_DETERMINERS}{_SUBMISSIONS}{_TAIL}"
    # "We don't want AI-generated PRs", "We no longer accept contributions from bots"
    r"|\b(?:do\s+not|don't|does\s+not|doesn't|will\s+not|won't|cannot|can't|not|no\s+longer"
    r"|never)\s+(?:currently\s+)?(?:accept|want|take|welcome|allow)(?:s|ing)?\s+"
    rf"{_DETERMINERS}{_TARGET}{_TAIL}"
    # "Agent-generated PRs will be closed", "PRs from bots are not accepted"
    rf"|\b{_TARGET}\s+(?:are|is|will\s+be|get|gets)\s+"
    r"(?:(?:not|no\s+longer)\s+(?:accepted|allowed|welcome|wanted)"
    r"|closed|rejected|banned|prohibited|forbidden|declined)"
    rf"(?:\s+without\s+(?:human\s+)?review)?{_TAIL}"
    r")",
    re.IGNORECASE,
)

__all__ = ["AUTOMATION_STOP"]
