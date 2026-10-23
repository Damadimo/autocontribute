"""Provider-native transcripts for multi-turn tool calling.

A transcript is bound to one model, one tool set and one set of instructions, and it only grows.
Every request replays all of its items byte for byte: that keeps the provider's prompt cache warm
and keeps earlier Anthropic thinking blocks valid, and editing an earlier item breaks both.
Callers truncate and scrub text before they append it; nothing here rewrites it later.

A conversation runs in this order:

1. ``start_transcript`` fixes the model, the kind (and with it the tools) and the instructions,
   and adds the task.
2. Reserve ``next_input_reservation(transcript)`` input tokens and the turn's output cap, then
   call ``TurnProvider.step``. A turn that stopped at ``max_output_tokens`` is not appended:
   send the same transcript again with a larger cap.
3. ``append_turn``. If the turn made no tool calls, ``append_user_text`` a nudge and go to 2.
4. Run the calls in order; ``read_submission`` validates a call of the kind's submit tool.
   ``append_tool_results`` adds one result per call, and any per-turn reminder. Go to 2.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from autocontribute.domain import DomainModel
from autocontribute.pricing import MODELS, ModelUsage, Provider
from autocontribute.submissions import (
    AgentSubmission,
    PolicySubmission,
    ReviewSubmission,
    SetupSubmission,
    TriageSubmission,
    strict_json_schema,
)

SubmissionT = TypeVar("SubmissionT", bound=BaseModel)
TranscriptKind = Literal["setup", "agent", "critic", "triage", "policy"]
ToolKind = Literal["shell", "edit", "submit"]
# Why the model stopped: it called tools, it ended its turn without one, or it hit the output
# limit, in which case the turn is retried and never appended.
TurnStop = Literal["tool_use", "end_turn", "max_output_tokens"]

_CALL_ID_PATTERN: Final = r"^[A-Za-z0-9_-]{1,128}$"
_RUN_ID_PATTERN: Final = r"^[A-Za-z0-9_-]{1,64}$"
# Framing tokens an item may cost beyond its own content, which its JSON bytes do not cover.
_ITEM_OVERHEAD_TOKENS: Final = 64
_RESERVATION_SLACK_TOKENS: Final = 1_024


@dataclass(frozen=True, slots=True)
class SubmitTool:
    name: str
    description: str
    arguments: type[BaseModel]


SUBMIT_TOOLS: Final[Mapping[TranscriptKind, SubmitTool]] = MappingProxyType(
    {
        "agent": SubmitTool(
            "submit",
            "Call this when the fix is complete and its tests pass, or with outcome skip to give "
            "up on the issue. The result reports the controller's checks of your change.",
            AgentSubmission,
        ),
        "setup": SubmitTool(
            "submit_setup",
            "Call this once the test command runs in this container. The controller replays the "
            "recipe in a fresh container before using it.",
            SetupSubmission,
        ),
        "critic": SubmitTool(
            "submit_review",
            "Call this once, with your verdict, after checking the change.",
            ReviewSubmission,
        ),
        "triage": SubmitTool(
            "submit_triage",
            "Call this once with your assessment of the issue.",
            TriageSubmission,
        ),
        "policy": SubmitTool(
            "submit_policy",
            "Call this once with your classification of the repository's AI contribution policy.",
            PolicySubmission,
        ),
    }
)
# The tools each kind of transcript declares, in request order. A transcript never changes them:
# both providers key their caches on the tool list, and Anthropic binds thinking blocks to it.
TOOL_SETS: Final[Mapping[TranscriptKind, tuple[ToolKind, ...]]] = MappingProxyType(
    {
        "setup": ("shell", "edit", "submit"),
        "agent": ("shell", "edit", "submit"),
        "critic": ("shell", "submit"),
        "triage": ("submit",),
        "policy": ("submit",),
    }
)
_SHELL_TOOLS: Final[Mapping[Provider, dict[str, JsonValue]]] = MappingProxyType(
    {
        "openai": {"type": "shell", "environment": {"type": "local"}},
        "anthropic": {"type": "bash_20250124", "name": "bash"},
    }
)
_EDIT_TOOLS: Final[Mapping[Provider, dict[str, JsonValue]]] = MappingProxyType(
    {
        "openai": {"type": "apply_patch"},
        "anthropic": {"type": "text_editor_20250728", "name": "str_replace_based_edit_tool"},
    }
)
# The two edit tools take different arguments, so their calls keep distinct names.
_EDIT_CALL_NAMES: Final[Mapping[Provider, str]] = MappingProxyType(
    {"openai": "apply_patch", "anthropic": "edit"}
)


def canonical_json(value: object) -> bytes:
    """Encode ``value`` as the worker IPC does; its length bounds the tokens it costs."""

    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def tool_definitions(provider: Provider, kind: TranscriptKind) -> list[dict[str, JsonValue]]:
    """Return the tools a transcript declares, in the provider's request form and order."""

    definitions: list[dict[str, JsonValue]] = []
    for tool in TOOL_SETS[kind]:
        if tool == "shell":
            definitions.append(copy.deepcopy(_SHELL_TOOLS[provider]))
        elif tool == "edit":
            definitions.append(copy.deepcopy(_EDIT_TOOLS[provider]))
        else:
            definitions.append(_submit_definition(provider, SUBMIT_TOOLS[kind]))
    return definitions


def tool_call_names(provider: Provider, kind: TranscriptKind) -> frozenset[str]:
    """Return the normalized names that the transcript's tool calls may carry."""

    names = {
        "shell": "shell",
        "edit": _EDIT_CALL_NAMES[provider],
        "submit": SUBMIT_TOOLS[kind].name,
    }
    return frozenset(names[tool] for tool in TOOL_SETS[kind])


def _submit_definition(provider: Provider, tool: SubmitTool) -> dict[str, JsonValue]:
    schema = strict_json_schema(tool.arguments)
    if provider == "openai":
        return {
            "type": "function",
            "name": tool.name,
            "description": tool.description,
            "parameters": schema,
            "strict": True,
        }
    return {
        "name": tool.name,
        "description": tool.description,
        "input_schema": schema,
        "strict": True,
    }


class _Value(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ToolCall(_Value):
    """One tool call with a normalized name and the provider's own argument object.

    ``shell`` takes ``{commands, timeout_ms?, max_output_length?}`` on OpenAI and ``{command}`` or
    ``{restart: true}`` on Anthropic. ``apply_patch`` (OpenAI) takes ``{type, path, diff?}`` and
    ``edit`` (Anthropic) takes the text editor's ``{command, path, ...}``. A submit tool takes its
    submission model's fields, which the caller validates with that model.
    """

    call_id: str = Field(pattern=_CALL_ID_PATTERN)
    name: str
    arguments: dict[str, JsonValue]


class ShellChunk(_Value):
    """Output of one command of an OpenAI shell call."""

    stdout: str
    stderr: str
    # None when the command hit its timeout; stdout and stderr then hold the partial output.
    exit_code: int | None


class ToolResult(_Value):
    """The result of one tool call, already truncated and scrubbed by the caller.

    OpenAI shell results are one chunk per command, in order, and report failures through their
    outcomes. Every other result is text, and ``is_error`` marks a failed call; OpenAI function
    outputs have no error flag, so their text has to say so.
    """

    call_id: str
    output: str | tuple[ShellChunk, ...]
    is_error: bool = False

    @model_validator(mode="after")
    def error_flag_needs_text(self) -> ToolResult:
        if self.is_error and not isinstance(self.output, str):
            raise ValueError("shell chunks report failures through their exit outcomes")
        return self


class Turn(_Value):
    """One model response, normalized.

    ``output_items`` are the provider-native items to replay: Responses output items on OpenAI,
    the message's content blocks on Anthropic.
    """

    stop: TurnStop
    output_items: tuple[dict[str, JsonValue], ...]
    tool_calls: tuple[ToolCall, ...]
    response_id: str
    model: str
    usage: ModelUsage

    @model_validator(mode="after")
    def calls_match_the_stop(self) -> Turn:
        if (self.stop == "tool_use") != bool(self.tool_calls):
            raise ValueError("a turn has tool calls exactly when it stopped for tool use")
        if self.stop == "max_output_tokens" and self.output_items:
            raise ValueError("a turn cut off at its output limit carries no output items")
        call_ids = [call.call_id for call in self.tool_calls]
        if len(set(call_ids)) != len(call_ids):
            raise ValueError("tool call IDs must be unique within a turn")
        return self


class Transcript(DomainModel):
    """One conversation with one model, replayed in full on every request.

    The ``prior_*`` fields describe the last turn and the ``appended_*`` fields what was added
    since, which is what ``next_input_reservation`` needs.
    """

    model: str
    kind: TranscriptKind
    # Names the run in the provider's prompt cache key.
    run_id: str = Field(pattern=_RUN_ID_PATTERN)
    instructions: str
    items: list[dict[str, JsonValue]] = Field(default_factory=list)
    # Calls of the last turn that still need results; no request is valid until they have them.
    pending_calls: list[ToolCall] = Field(default_factory=list)
    prior_input_tokens: int | None = None
    prior_output_tokens: int = 0
    prior_output_items: int = 0
    appended_bytes: int = 0
    appended_items: int = 0

    @field_validator("model")
    @classmethod
    def model_is_in_the_table(cls, value: str) -> str:
        if value not in MODELS:
            raise ValueError("model must be an id from the built-in model table")
        return value

    @property
    def provider(self) -> Provider:
        return MODELS[self.model].provider

    @property
    def awaiting_model(self) -> bool:
        """Whether the next step is a model request: there is something new and no open call."""

        return self.appended_items > 0 and not self.pending_calls


def start_transcript(
    *,
    model: str,
    kind: TranscriptKind,
    run_id: str,
    instructions: str,
    task: str,
) -> Transcript:
    """Start a conversation of one kind with ``model``, with ``task`` as its first message.

    ``model`` is an id from the built-in table, and ``run_id`` names the run in the provider's
    prompt cache key. ``instructions`` must stay byte-stable for the whole conversation, so
    per-run facts belong in ``task``.
    """

    transcript = Transcript(model=model, kind=kind, run_id=run_id, instructions=instructions)
    append_user_text(transcript, task)
    return transcript


def append_user_text(transcript: Transcript, text: str) -> None:
    """Append a user message: a nudge after a turn without tool calls, or the critic's blockers.
    Per-turn reminders go with the tool results (``append_tool_results``)."""

    if transcript.pending_calls:
        raise ValueError("tool calls are waiting for their results")
    item: dict[str, JsonValue]
    if transcript.provider == "openai":
        item = _openai_user_message(text)
    else:
        item = {"role": "user", "content": [{"type": "text", "text": text}]}
    _append(transcript, [item], counted_items=1)


def append_turn(transcript: Transcript, turn: Turn) -> None:
    """Append a model turn's output and hold its tool calls until their results arrive."""

    if turn.stop == "max_output_tokens":
        raise ValueError("a turn cut off at its output limit is retried, never appended")
    if not transcript.awaiting_model:
        raise ValueError("the transcript is not waiting for a model turn")
    output_items = [copy.deepcopy(item) for item in turn.output_items]
    if transcript.provider == "openai":
        transcript.items.extend(output_items)
    else:
        transcript.items.append({"role": "assistant", "content": list(output_items)})
    transcript.pending_calls = list(turn.tool_calls)
    transcript.prior_input_tokens = turn.usage.input_tokens
    transcript.prior_output_tokens = turn.usage.output_tokens
    transcript.prior_output_items = len(output_items)
    transcript.appended_bytes = 0
    transcript.appended_items = 0


def append_tool_results(
    transcript: Transcript,
    results: Sequence[ToolResult],
    *,
    reminder: str | None = None,
) -> None:
    """Append one result for each pending tool call, in call order.

    ``reminder`` is per-turn guidance such as the turns left. It follows the results: on
    Anthropic as a text block in their user message, on OpenAI as a user message of its own.
    Like everything else it stays in the transcript; a later turn adds a new one.
    """

    calls = transcript.pending_calls
    if not calls:
        raise ValueError("the transcript has no pending tool calls")
    if [result.call_id for result in results] != [call.call_id for call in calls]:
        raise ValueError("results must answer every pending tool call once, in call order")
    pairs = zip(calls, results, strict=True)
    items: list[dict[str, JsonValue]]
    if transcript.provider == "openai":
        items = [_openai_result(call, result) for call, result in pairs]
        if reminder is not None:
            items.append(_openai_user_message(reminder))
    else:
        # All results of one turn go back in one user message.
        content: list[JsonValue] = [_anthropic_result(call, result) for call, result in pairs]
        if reminder is not None:
            content.append({"type": "text", "text": reminder})
        items = [{"role": "user", "content": content}]
    transcript.pending_calls = []
    counted_items = len(results) if reminder is None else len(results) + 1
    _append(transcript, items, counted_items=counted_items)


def read_submission(call: ToolCall, submission: type[SubmissionT]) -> SubmissionT:
    """Validate a call of a submit tool with its submission model, such as ``AgentSubmission``.

    Strict tool schemas leave out bounds and rules across fields, so they are checked here.
    Raises ``ValueError`` (pydantic's ``ValidationError`` for invalid arguments): send its text
    back as an error result for the call, and the model can submit again.
    """

    tool = next((tool for tool in SUBMIT_TOOLS.values() if tool.arguments is submission), None)
    if tool is None:
        raise ValueError(f"{submission.__name__} is not a submission model")
    if call.name != tool.name:
        raise ValueError(f"the call is not a {tool.name} call")
    return submission.model_validate(call.arguments)


def next_input_reservation(transcript: Transcript) -> int:
    """Return an upper bound on the input tokens of the transcript's next request.

    JSON bytes bound tokens. The first request sends the instructions, the tools and the items.
    A later request replays the previous one, billed as that turn's input, and the turn's
    output, plus what was appended since; every replayed output item and every appended item
    may also cost framing tokens beyond its bytes.
    """

    if transcript.prior_input_tokens is None:
        tools = tool_definitions(transcript.provider, transcript.kind)
        sent: tuple[object, ...] = (transcript.instructions, tools, transcript.items)
        return sum(len(canonical_json(part)) for part in sent) + _RESERVATION_SLACK_TOKENS
    return (
        transcript.prior_input_tokens
        + transcript.prior_output_tokens
        + transcript.appended_bytes
        + _ITEM_OVERHEAD_TOKENS * (transcript.prior_output_items + transcript.appended_items)
        + _RESERVATION_SLACK_TOKENS
    )


def _append(
    transcript: Transcript, items: list[dict[str, JsonValue]], *, counted_items: int
) -> None:
    transcript.items.extend(items)
    transcript.appended_bytes += sum(len(canonical_json(item)) for item in items)
    transcript.appended_items += counted_items


def _text(result: ToolResult) -> str:
    if not isinstance(result.output, str):
        raise ValueError("only OpenAI shell results are output chunks")
    return result.output


def _openai_user_message(text: str) -> dict[str, JsonValue]:
    return {"type": "message", "role": "user", "content": [{"type": "input_text", "text": text}]}


def _openai_result(call: ToolCall, result: ToolResult) -> dict[str, JsonValue]:
    if call.name == "shell":
        if isinstance(result.output, str) or not result.output:
            raise ValueError("an OpenAI shell result needs one output chunk per command")
        item: dict[str, JsonValue] = {
            "type": "shell_call_output",
            "call_id": call.call_id,
            "output": [_shell_chunk(chunk) for chunk in result.output],
        }
        # The API asks for the call's own limit back on its output.
        max_output_length = call.arguments.get("max_output_length")
        if max_output_length is not None:
            item["max_output_length"] = max_output_length
        return item
    if call.name == "apply_patch":
        return {
            "type": "apply_patch_call_output",
            "call_id": call.call_id,
            "status": "failed" if result.is_error else "completed",
            "output": _text(result),
        }
    return {"type": "function_call_output", "call_id": call.call_id, "output": _text(result)}


def _shell_chunk(chunk: ShellChunk) -> dict[str, JsonValue]:
    outcome: dict[str, JsonValue] = (
        {"type": "timeout"}
        if chunk.exit_code is None
        else {"type": "exit", "exit_code": chunk.exit_code}
    )
    return {"stdout": chunk.stdout, "stderr": chunk.stderr, "outcome": outcome}


def _anthropic_result(call: ToolCall, result: ToolResult) -> dict[str, JsonValue]:
    block: dict[str, JsonValue] = {
        "type": "tool_result",
        "tool_use_id": call.call_id,
        "content": _text(result),
    }
    if result.is_error:
        block["is_error"] = True
    return block


__all__ = [
    "SUBMIT_TOOLS",
    "TOOL_SETS",
    "ShellChunk",
    "SubmitTool",
    "ToolCall",
    "ToolKind",
    "ToolResult",
    "Transcript",
    "TranscriptKind",
    "Turn",
    "TurnStop",
    "append_tool_results",
    "append_turn",
    "append_user_text",
    "canonical_json",
    "next_input_reservation",
    "read_submission",
    "start_transcript",
    "tool_call_names",
    "tool_definitions",
]
