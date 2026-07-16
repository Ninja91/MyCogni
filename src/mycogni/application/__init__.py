"""Application commands, queries, services, ports, and data-transfer types.

Application code may depend on the domain and abstractions it owns. It must not
depend on concrete adapters, entrypoints, or the bootstrap composition root.
"""

from mycogni.application.diagnostics import (
    ActionCode,
    ConnectorCode,
    ConnectorVersionCode,
    DiagnosticComponent,
    DiagnosticEvent,
    DiagnosticLevel,
    DiagnosticResultCode,
    DiagnosticSink,
    ErrorCategory,
    EventId,
    FieldName,
    classify_exception,
)
from mycogni.application.ports import Clock, UnitOfWork

__all__ = (
    "ActionCode",
    "Clock",
    "ConnectorCode",
    "ConnectorVersionCode",
    "DiagnosticComponent",
    "DiagnosticEvent",
    "DiagnosticLevel",
    "DiagnosticResultCode",
    "DiagnosticSink",
    "ErrorCategory",
    "EventId",
    "FieldName",
    "UnitOfWork",
    "classify_exception",
)
