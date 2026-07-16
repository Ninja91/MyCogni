"""Framework-independent domain rules and value types.

Domain modules may use the Python standard library and other domain modules.
They must not import application orchestration, adapters, entrypoints, bootstrap
composition, or third-party frameworks.
"""

__all__: tuple[str, ...] = ()
