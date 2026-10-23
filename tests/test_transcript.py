from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import JsonValue, ValidationError

from autocontribute.pricing import ModelUsage
from autocontribute.submissions import AgentSubmission, ReviewSubmission, strict_json_schema
from autocontribute.transcript import (
    SUBMIT_TOOLS,
    ShellChunk,
    ToolCall,
    ToolResult,
    Transcript,
    TranscriptKind,
    Turn,
    append_tool_results,
    append_turn,
    append_user_text,
    canonical_json,
    next_input_reservation,
    tool_call_names,
    tool_definitions,
)

_RUN_ID = "0123456789abcdef"
_USAGE = ModelUsage(
    input_tokens=2_412,
    cached_input_tokens=1_920,
    cache_write_tokens=380,
    output_tokens=160,
    reasoning_tokens=96,
    total_tokens=2_572,
)
# Output items shaped like the 2026-10-22 gpt-5.6-sol probe, after created_by is stripped.
_OPENAI_REASONING: dict[str, JsonValue] = {
    "id": "rs_68f9a1c2d3",
    "type": "reasoning",
    "summary": [],
    "encrypted_content": "gAAAAABo-opaque-reasoning",
}
_OPENAI_SHELL_CALL: dict[str, JsonValue] = {
    "id": "sh_68f9a1c2d4",
    "type": "shell_call",
    "call_id": "call_9d14ac6f2b73485e",
    "action": {
        "commands": ["cat hello.py", "python hello.py"],
        "timeout_ms": 120_000,
        "max_output_length": 4_096,
    },
    "status": "in_progress",
}
_OPENAI_PATCH_CALL: dict[str, JsonValue] = {
    "id": "apc_68f9a1c2d5",
    "type": "apply_patch_call",
    "call_id": "call_Rjsqzz96C5xzPb0j",
    "operation": {
        "type": "update_file",
        "path": "/workspace/hello.py",
        "diff": "@@\n-print('hi')\n+print('Hello, world!')\n",
    },
    "status": "completed",
}
_OPENAI_SUBMIT_CALL: dict[str, JsonValue] = {
    "id": "fc_68f9a1c2d6",
    "type": "function_call",
    "call_id": "call_3ef1b8c79a4d6520",
    "name": "submit",
    "arguments": '{"outcome":"skip"}',
    "status": "completed",
}
_ANTHROPIC_THINKING: dict[str, JsonValue] = {
    "type": "thinking",
    "thinking": "",
    "signature": "EqQBCgIYAhIM1gbcDa9GJwZA2b3h",
}
_ANTHROPIC_BASH_CALL: dict[str, JsonValue] = {
    "type": "tool_use",
    "id": "toolu_01A09q90qw90lq917835lq9",
    "name": "bash",
    "input": {"command": "cat hello.py"},
}


def _transcript(model: str = "gpt-5.6-sol", kind: TranscriptKind = "agent") -> Transcript:
    return Transcript(model=model, kind=kind, run_id=_RUN_ID, instructions="Fix the issue.")


def _openai_turn(*items: dict[str, JsonValue]) -> Turn:
    calls = []
    for item in items:
        if item["type"] == "shell_call":
            calls.append(ToolCall(call_id=item["call_id"], name="shell", arguments=item["action"]))
        elif item["type"] == "apply_patch_call":
            calls.append(
                ToolCall(call_id=item["call_id"], name="apply_patch", arguments=item["operation"])
            )
        elif item["type"] == "function_call":
            calls.append(
                ToolCall(call_id=item["call_id"], name="submit", arguments={"outcome": "skip"})
            )
    return Turn(
        stop="tool_use" if calls else "end_turn",
        output_items=items,
        tool_calls=tuple(calls),
        response_id="resp_68f9a1c2d2",
        model="gpt-5.6-sol",
        usage=_USAGE,
    )


def _anthropic_turn() -> Turn:
    return Turn(
        stop="tool_use",
        output_items=(_ANTHROPIC_THINKING, _ANTHROPIC_BASH_CALL),
        tool_calls=(
            ToolCall(
                call_id="toolu_01A09q90qw90lq917835lq9",
                name="shell",
                arguments={"command": "cat hello.py"},
            ),
        ),
        response_id="msg_01XFDUDYJgAACzvnptvVoYEL",
        model="claude-opus-5-5",
        usage=_USAGE,
    )


def test_openai_agent_declares_local_shell_apply_patch_and_a_strict_submit_function() -> None:
    assert tool_definitions("openai", "agent") == [
        {"type": "shell", "environment": {"type": "local"}},
        {"type": "apply_patch"},
        {
            "type": "function",
            "name": "submit",
            "description": SUBMIT_TOOLS["agent"].description,
            "parameters": strict_json_schema(AgentSubmission),
            "strict": True,
        },
    ]


def test_anthropic_critic_declares_bash_and_a_strict_custom_submit_tool() -> None:
    assert tool_definitions("anthropic", "critic") == [
        {"type": "bash_20250124", "name": "bash"},
        {
            "name": "submit_review",
            "description": SUBMIT_TOOLS["critic"].description,
            "input_schema": strict_json_schema(ReviewSubmission),
            "strict": True,
        },
    ]


@pytest.mark.parametrize(
    ("kind", "openai_types", "anthropic_names"),
    [
        (
            "agent",
            ["shell", "apply_patch", "function"],
            ["bash", "str_replace_based_edit_tool", "submit"],
        ),
        (
            "setup",
            ["shell", "apply_patch", "function"],
            ["bash", "str_replace_based_edit_tool", "submit_setup"],
        ),
        ("critic", ["shell", "function"], ["bash", "submit_review"]),
        ("triage", ["function"], ["submit_triage"]),
        ("policy", ["function"], ["submit_policy"]),
    ],
)
def test_each_kind_declares_its_tools_in_a_fixed_order(
    kind: TranscriptKind,
    openai_types: list[str],
    anthropic_names: list[str],
) -> None:
    assert [tool["type"] for tool in tool_definitions("openai", kind)] == openai_types
    assert [tool["name"] for tool in tool_definitions("anthropic", kind)] == anthropic_names


def test_tool_call_names_are_normalized_per_provider() -> None:
    assert tool_call_names("openai", "agent") == {"shell", "apply_patch", "submit"}
    assert tool_call_names("anthropic", "agent") == {"shell", "edit", "submit"}
    assert tool_call_names("openai", "critic") == {"shell", "submit_review"}
    assert tool_call_names("anthropic", "triage") == {"submit_triage"}
    assert tool_call_names("openai", "policy") == {"submit_policy"}


def test_tool_definitions_are_byte_stable_and_returned_as_copies() -> None:
    first = tool_definitions("openai", "setup")
    first[0]["environment"] = {"type": "container_auto"}

    assert tool_definitions("openai", "setup")[0] == {
        "type": "shell",
        "environment": {"type": "local"},
    }
    assert canonical_json(tool_definitions("anthropic", "setup")) == canonical_json(
        tool_definitions("anthropic", "setup")
    )


def test_transcript_is_bound_to_a_table_model_and_a_safe_run_id() -> None:
    assert _transcript().provider == "openai"
    assert _transcript("claude-sonnet-5-5").provider == "anthropic"
    with pytest.raises(ValidationError, match="built-in model table"):
        _transcript("gpt-5.6")
    with pytest.raises(ValidationError, match="run_id"):
        Transcript(model="gpt-5.6-sol", kind="agent", run_id="../x", instructions="Fix it.")


@pytest.mark.parametrize(
    ("model", "item"),
    [
        (
            "gpt-5.6-terra",
            {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "Fix issue 12."}],
            },
        ),
        (
            "claude-opus-5-5",
            {"role": "user", "content": [{"type": "text", "text": "Fix issue 12."}]},
        ),
    ],
)
def test_user_text_is_a_provider_native_user_message(model: str, item: dict[str, Any]) -> None:
    transcript = _transcript(model)

    append_user_text(transcript, "Fix issue 12.")

    assert transcript.items == [item]
    assert transcript.appended_items == 1
    assert transcript.appended_bytes == len(canonical_json(item))
    assert transcript.awaiting_model


def test_openai_turn_appends_its_output_items_and_holds_its_calls() -> None:
    transcript = _transcript()
    append_user_text(transcript, "Fix issue 12.")
    turn = _openai_turn(_OPENAI_REASONING, _OPENAI_SHELL_CALL, _OPENAI_PATCH_CALL)

    append_turn(transcript, turn)

    assert transcript.items[1:] == [_OPENAI_REASONING, _OPENAI_SHELL_CALL, _OPENAI_PATCH_CALL]
    assert transcript.pending_calls == list(turn.tool_calls)
    assert transcript.prior_input_tokens == 2_412
    assert transcript.prior_output_tokens == 160
    assert transcript.prior_output_items == 3
    assert (transcript.appended_bytes, transcript.appended_items) == (0, 0)
    assert not transcript.awaiting_model


def test_anthropic_turn_is_one_assistant_message_with_its_content_blocks() -> None:
    transcript = _transcript("claude-opus-5-5")
    append_user_text(transcript, "Fix issue 12.")

    append_turn(transcript, _anthropic_turn())

    assert transcript.items[1] == {
        "role": "assistant",
        "content": [_ANTHROPIC_THINKING, _ANTHROPIC_BASH_CALL],
    }
    assert transcript.prior_output_items == 2


def test_openai_tool_results_become_native_call_outputs() -> None:
    transcript = _transcript()
    append_user_text(transcript, "Fix issue 12.")
    append_turn(
        transcript,
        _openai_turn(_OPENAI_SHELL_CALL, _OPENAI_PATCH_CALL, _OPENAI_SUBMIT_CALL),
    )
    before = len(transcript.items)

    append_tool_results(
        transcript,
        [
            ToolResult(
                call_id="call_9d14ac6f2b73485e",
                output=(
                    ShellChunk(stdout="print('hi')\n", stderr="", exit_code=0),
                    ShellChunk(stdout="hi\n", stderr="slow", exit_code=None),
                ),
            ),
            ToolResult(
                call_id="call_Rjsqzz96C5xzPb0j",
                output="Invalid context at line 1",
                is_error=True,
            ),
            ToolResult(call_id="call_3ef1b8c79a4d6520", output="Error: pr_title is missing."),
        ],
    )

    appended = transcript.items[before:]
    assert appended == [
        {
            "type": "shell_call_output",
            "call_id": "call_9d14ac6f2b73485e",
            "output": [
                {
                    "stdout": "print('hi')\n",
                    "stderr": "",
                    "outcome": {"type": "exit", "exit_code": 0},
                },
                {"stdout": "hi\n", "stderr": "slow", "outcome": {"type": "timeout"}},
            ],
            "max_output_length": 4_096,
        },
        {
            "type": "apply_patch_call_output",
            "call_id": "call_Rjsqzz96C5xzPb0j",
            "status": "failed",
            "output": "Invalid context at line 1",
        },
        {
            "type": "function_call_output",
            "call_id": "call_3ef1b8c79a4d6520",
            "output": "Error: pr_title is missing.",
        },
    ]
    assert transcript.pending_calls == []
    assert transcript.appended_items == 3
    assert transcript.appended_bytes == sum(len(canonical_json(item)) for item in appended)
    assert transcript.awaiting_model


def test_openai_shell_output_echoes_max_output_length_only_when_the_call_set_it() -> None:
    shell_call = copy.deepcopy(_OPENAI_SHELL_CALL)
    assert isinstance(shell_call["action"], dict)
    del shell_call["action"]["max_output_length"]
    transcript = _transcript()
    append_user_text(transcript, "Fix issue 12.")
    append_turn(transcript, _openai_turn(shell_call))

    append_tool_results(
        transcript,
        [
            ToolResult(
                call_id="call_9d14ac6f2b73485e",
                output=(ShellChunk(stdout="", stderr="", exit_code=0),) * 2,
            )
        ],
    )

    assert "max_output_length" not in transcript.items[-1]


def test_anthropic_results_and_reminder_of_one_turn_share_one_user_message() -> None:
    transcript = _transcript("claude-opus-5-5")
    append_user_text(transcript, "Fix issue 12.")
    second_call = {**_ANTHROPIC_BASH_CALL, "id": "toolu_02B", "input": {"command": "ls"}}
    turn = Turn(
        stop="tool_use",
        output_items=(_ANTHROPIC_BASH_CALL, second_call),
        tool_calls=(
            ToolCall(call_id="toolu_01A09q90qw90lq917835lq9", name="shell", arguments={}),
            ToolCall(call_id="toolu_02B", name="shell", arguments={}),
        ),
        response_id="msg_01",
        model="claude-opus-5-5",
        usage=_USAGE,
    )
    append_turn(transcript, turn)

    append_tool_results(
        transcript,
        [
            ToolResult(call_id="toolu_01A09q90qw90lq917835lq9", output="print('hi')\n"),
            ToolResult(call_id="toolu_02B", output="ls: cannot access", is_error=True),
        ],
        reminder="10 turns left; submit soon.",
    )

    assert transcript.items[2:] == [
        {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_01A09q90qw90lq917835lq9",
                    "content": "print('hi')\n",
                },
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_02B",
                    "content": "ls: cannot access",
                    "is_error": True,
                },
                {"type": "text", "text": "10 turns left; submit soon."},
            ],
        },
    ]
    assert transcript.appended_items == 3
    assert transcript.appended_bytes == len(canonical_json(transcript.items[2]))


def test_openai_reminder_is_a_user_message_after_the_results() -> None:
    transcript = _transcript()
    append_user_text(transcript, "Fix issue 12.")
    append_turn(transcript, _openai_turn(_OPENAI_SUBMIT_CALL))

    append_tool_results(
        transcript,
        [ToolResult(call_id="call_3ef1b8c79a4d6520", output="Error: pr_title is missing.")],
        reminder="10 turns left; submit soon.",
    )

    assert transcript.items[-2:] == [
        {
            "type": "function_call_output",
            "call_id": "call_3ef1b8c79a4d6520",
            "output": "Error: pr_title is missing.",
        },
        {
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": "10 turns left; submit soon."}],
        },
    ]
    assert transcript.appended_items == 2


@pytest.mark.parametrize(
    "call_ids",
    [
        [],
        ["call_9d14ac6f2b73485e"],
        ["call_Rjsqzz96C5xzPb0j", "call_9d14ac6f2b73485e"],
        ["call_9d14ac6f2b73485e", "call_Rjsqzz96C5xzPb0j", "call_9d14ac6f2b73485e"],
    ],
    ids=["none", "missing", "reordered", "repeated"],
)
def test_results_must_answer_every_pending_call_once_in_order(call_ids: list[str]) -> None:
    transcript = _transcript()
    append_user_text(transcript, "Fix issue 12.")
    append_turn(transcript, _openai_turn(_OPENAI_SHELL_CALL, _OPENAI_PATCH_CALL))
    before = transcript.model_copy(deep=True)

    with pytest.raises(ValueError, match="every pending tool call once"):
        append_tool_results(
            transcript, [ToolResult(call_id=call_id, output="done") for call_id in call_ids]
        )

    assert transcript == before


def test_results_need_pending_calls() -> None:
    transcript = _transcript()
    append_user_text(transcript, "Fix issue 12.")

    with pytest.raises(ValueError, match="no pending tool calls"):
        append_tool_results(transcript, [])


@pytest.mark.parametrize(
    ("model", "item", "output", "error"),
    [
        ("gpt-5.6-sol", _OPENAI_SHELL_CALL, "exit 0", "one output chunk per command"),
        ("gpt-5.6-sol", _OPENAI_SHELL_CALL, (), "one output chunk per command"),
        (
            "gpt-5.6-sol",
            _OPENAI_PATCH_CALL,
            (ShellChunk(stdout="", stderr="", exit_code=0),),
            "only OpenAI shell results",
        ),
        (
            "claude-opus-5-5",
            _ANTHROPIC_BASH_CALL,
            (ShellChunk(stdout="", stderr="", exit_code=0),),
            "only OpenAI shell results",
        ),
    ],
    ids=["openai-shell-text", "openai-shell-empty", "openai-patch-chunks", "anthropic-chunks"],
)
def test_result_output_must_fit_the_call(
    model: str,
    item: dict[str, JsonValue],
    output: str | tuple[ShellChunk, ...],
    error: str,
) -> None:
    transcript = _transcript(model)
    append_user_text(transcript, "Fix issue 12.")
    turn = _anthropic_turn() if model.startswith("claude") else _openai_turn(item)
    append_turn(transcript, turn)
    call_id = turn.tool_calls[0].call_id

    with pytest.raises(ValueError, match=error):
        append_tool_results(transcript, [ToolResult(call_id=call_id, output=output)])


def test_shell_chunks_cannot_carry_the_error_flag() -> None:
    with pytest.raises(ValidationError, match="exit outcomes"):
        ToolResult(
            call_id="call_1",
            output=(ShellChunk(stdout="", stderr="boom", exit_code=1),),
            is_error=True,
        )


def test_a_turn_cut_off_at_its_output_limit_is_never_appended() -> None:
    transcript = _transcript()
    append_user_text(transcript, "Fix issue 12.")
    reserved = next_input_reservation(transcript)
    turn = Turn(
        stop="max_output_tokens",
        output_items=(),
        tool_calls=(),
        response_id="resp_1",
        model="gpt-5.6-sol",
        usage=_USAGE,
    )

    with pytest.raises(ValueError, match="retried, never appended"):
        append_turn(transcript, turn)
    # The retry sends the same input, so it reserves the same amount.
    assert next_input_reservation(transcript) == reserved
    assert transcript.awaiting_model
    assert len(transcript.items) == 1


def test_turns_alternate_with_the_callers_side() -> None:
    transcript = _transcript()
    with pytest.raises(ValueError, match="not waiting for a model turn"):
        append_turn(transcript, _openai_turn(_OPENAI_REASONING))

    append_user_text(transcript, "Fix issue 12.")
    append_turn(transcript, _openai_turn(_OPENAI_REASONING))
    with pytest.raises(ValueError, match="not waiting for a model turn"):
        append_turn(transcript, _openai_turn(_OPENAI_REASONING))

    append_user_text(transcript, "Continue the task; call submit when you are done.")
    append_turn(transcript, _openai_turn(_OPENAI_SHELL_CALL))
    with pytest.raises(ValueError, match="waiting for their results"):
        append_user_text(transcript, "Submit now.")


def test_appending_never_changes_earlier_items() -> None:
    transcript = _transcript()
    append_user_text(transcript, "Fix issue 12.")
    snapshots = [canonical_json(transcript.items)]
    turn = _openai_turn(_OPENAI_REASONING, _OPENAI_SHELL_CALL)
    append_turn(transcript, turn)
    snapshots.append(canonical_json(transcript.items))
    append_tool_results(
        transcript,
        [
            ToolResult(
                call_id="call_9d14ac6f2b73485e",
                output=(ShellChunk(stdout="hi\n", stderr="", exit_code=0),) * 2,
            )
        ],
    )
    snapshots.append(canonical_json(transcript.items))
    append_turn(transcript, _openai_turn(_OPENAI_SUBMIT_CALL))
    turn.output_items[0]["encrypted_content"] = "tampered"

    final = canonical_json(transcript.items)
    for snapshot in snapshots:
        assert final.startswith(snapshot[:-1])
    assert transcript.items[1]["encrypted_content"] == "gAAAAABo-opaque-reasoning"


def test_first_reservation_counts_instructions_tools_and_items() -> None:
    transcript = _transcript(kind="triage")
    append_user_text(transcript, "Assess issue 12.")

    expected = (
        len(canonical_json("Fix the issue."))
        + len(canonical_json(tool_definitions("openai", "triage")))
        + len(canonical_json(transcript.items))
        + 1_024
    )
    assert next_input_reservation(transcript) == expected


def test_later_reservations_add_the_last_turn_and_what_followed_it() -> None:
    transcript = _transcript("claude-opus-5-5")
    append_user_text(transcript, "Fix issue 12.")
    append_turn(transcript, _anthropic_turn())
    append_tool_results(
        transcript,
        [ToolResult(call_id="toolu_01A09q90qw90lq917835lq9", output="print('hi')\n")],
    )
    append_user_text(transcript, "10 turns left.")
    appended_bytes = len(canonical_json(transcript.items[2])) + len(
        canonical_json(transcript.items[3])
    )

    assert transcript.appended_bytes == appended_bytes
    # prior input and output, appended bytes, 64 per replayed or appended item, and the slack
    assert next_input_reservation(transcript) == 2_412 + 160 + appended_bytes + 64 * (2 + 2) + 1_024


@pytest.mark.parametrize(
    ("stop", "items", "calls", "error"),
    [
        ("end_turn", (), (ToolCall(call_id="call_1", name="shell", arguments={}),), "exactly"),
        ("tool_use", (), (), "exactly"),
        ("max_output_tokens", ({"type": "reasoning"},), (), "carries no output items"),
        (
            "tool_use",
            (),
            (
                ToolCall(call_id="call_1", name="shell", arguments={}),
                ToolCall(call_id="call_1", name="apply_patch", arguments={}),
            ),
            "unique",
        ),
    ],
    ids=["calls-without-tool-use", "tool-use-without-calls", "cut-off-with-items", "repeated-id"],
)
def test_turn_rejects_inconsistent_shapes(
    stop: str,
    items: tuple[dict[str, JsonValue], ...],
    calls: tuple[ToolCall, ...],
    error: str,
) -> None:
    with pytest.raises(ValidationError, match=error):
        Turn(
            stop=stop,
            output_items=items,
            tool_calls=calls,
            response_id="resp_1",
            model="gpt-5.6-sol",
            usage=_USAGE,
        )


@pytest.mark.parametrize("call_id", ["", "call 1", "call/1", "c" * 129])
def test_tool_call_ids_are_bounded_identifiers(call_id: str) -> None:
    with pytest.raises(ValidationError, match="call_id"):
        ToolCall(call_id=call_id, name="shell", arguments={})
