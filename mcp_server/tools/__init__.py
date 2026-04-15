"""SIFT forensic tool wrappers with architectural guardrails.

Note: the 30+ tool integrations live inline in ``mcp_server/server.py`` rather
than being split into per-tool modules here. Keeping the dispatcher, guardrail
checks, and tool handlers in one file makes the security boundary easier to
audit. This package exists as a stable import anchor for future splitting if
``server.py`` grows too large.
"""
