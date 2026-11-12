from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Verdict(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    VERDICT_UNSPECIFIED: _ClassVar[Verdict]
    VERDICT_ALLOW: _ClassVar[Verdict]
    VERDICT_BLOCK: _ClassVar[Verdict]
VERDICT_UNSPECIFIED: Verdict
VERDICT_ALLOW: Verdict
VERDICT_BLOCK: Verdict

class Scope(_message.Message):
    __slots__ = ("task", "allowed_operations", "allowed_resources", "deny_operations")
    TASK_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_OPERATIONS_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_RESOURCES_FIELD_NUMBER: _ClassVar[int]
    DENY_OPERATIONS_FIELD_NUMBER: _ClassVar[int]
    task: str
    allowed_operations: _containers.RepeatedScalarFieldContainer[str]
    allowed_resources: _containers.RepeatedScalarFieldContainer[str]
    deny_operations: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, task: _Optional[str] = ..., allowed_operations: _Optional[_Iterable[str]] = ..., allowed_resources: _Optional[_Iterable[str]] = ..., deny_operations: _Optional[_Iterable[str]] = ...) -> None: ...

class HistoryEntry(_message.Message):
    __slots__ = ("tool_name", "arguments_json", "verdict")
    TOOL_NAME_FIELD_NUMBER: _ClassVar[int]
    ARGUMENTS_JSON_FIELD_NUMBER: _ClassVar[int]
    VERDICT_FIELD_NUMBER: _ClassVar[int]
    tool_name: str
    arguments_json: str
    verdict: str
    def __init__(self, tool_name: _Optional[str] = ..., arguments_json: _Optional[str] = ..., verdict: _Optional[str] = ...) -> None: ...

class EvaluateRequest(_message.Message):
    __slots__ = ("request_id", "agent_id", "user_id", "session_id", "task", "scope", "tool_name", "arguments_json", "action_type", "operation", "tier1_reasoning", "history")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    TASK_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    TOOL_NAME_FIELD_NUMBER: _ClassVar[int]
    ARGUMENTS_JSON_FIELD_NUMBER: _ClassVar[int]
    ACTION_TYPE_FIELD_NUMBER: _ClassVar[int]
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    TIER1_REASONING_FIELD_NUMBER: _ClassVar[int]
    HISTORY_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    agent_id: str
    user_id: str
    session_id: str
    task: str
    scope: Scope
    tool_name: str
    arguments_json: str
    action_type: str
    operation: str
    tier1_reasoning: str
    history: _containers.RepeatedCompositeFieldContainer[HistoryEntry]
    def __init__(self, request_id: _Optional[str] = ..., agent_id: _Optional[str] = ..., user_id: _Optional[str] = ..., session_id: _Optional[str] = ..., task: _Optional[str] = ..., scope: _Optional[_Union[Scope, _Mapping]] = ..., tool_name: _Optional[str] = ..., arguments_json: _Optional[str] = ..., action_type: _Optional[str] = ..., operation: _Optional[str] = ..., tier1_reasoning: _Optional[str] = ..., history: _Optional[_Iterable[_Union[HistoryEntry, _Mapping]]] = ...) -> None: ...

class EvaluateResponse(_message.Message):
    __slots__ = ("verdict", "confidence", "reasoning", "reversible", "policy_name", "severity", "model", "latency_ms")
    VERDICT_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    REASONING_FIELD_NUMBER: _ClassVar[int]
    REVERSIBLE_FIELD_NUMBER: _ClassVar[int]
    POLICY_NAME_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    MODEL_FIELD_NUMBER: _ClassVar[int]
    LATENCY_MS_FIELD_NUMBER: _ClassVar[int]
    verdict: Verdict
    confidence: float
    reasoning: str
    reversible: bool
    policy_name: str
    severity: str
    model: str
    latency_ms: int
    def __init__(self, verdict: _Optional[_Union[Verdict, str]] = ..., confidence: _Optional[float] = ..., reasoning: _Optional[str] = ..., reversible: _Optional[bool] = ..., policy_name: _Optional[str] = ..., severity: _Optional[str] = ..., model: _Optional[str] = ..., latency_ms: _Optional[int] = ...) -> None: ...
