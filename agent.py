# agent.py
# Purpose: AI agent implementation with deliberately seeded security vulnerabilities.
#          Used as a static analysis target for the aisec repository scan.
#          DO NOT deploy — this file is intentionally insecure for testing only.
# Author: Thamizhmani
# Date: 2026-09-16
# Modified: 2026-09-17 — Add LangChain AgentExecutor wrapper for scanner detection.

import os
import openai
import anthropic

# ── VULNERABILITY R-01: Hardcoded OpenAI API key ──────────────────────────────
# Secret scanner should flag this as CRITICAL.
OPENAI_API_KEY = "sk-proj-abcdefghijklmnop1234567890ABCDEFGHIJKLMNOP12345678"

# ── VULNERABILITY R-02: Hardcoded Anthropic API key ───────────────────────────
# Secret scanner should flag this as CRITICAL.
ANTHROPIC_API_KEY = "ant-api01-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

openai.api_key = OPENAI_API_KEY

SYSTEM_PROMPT = (
    "You are a customer service AI agent. "
    "You have access to tools: read_file, execute_query, send_email, delete_record."
)

# ── VULNERABILITY: No input validation before passing to LLM ─────────────────
def get_ai_response(user_input: str) -> str:
    """Send user_input directly to LLM without validation or sanitization."""
    client = openai.OpenAI(api_key=OPENAI_API_KEY)
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_input},  # unvalidated external input
        ],
        max_tokens=4096,  # no output token limit guard
    )
    return response.choices[0].message.content


# ── VULNERABILITY: Anthropic client with hardcoded key ────────────────────────
def get_claude_response(user_input: str) -> str:
    """Alternative agent path using Claude — also no input validation."""
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    message = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=4096,
        messages=[{"role": "user", "content": user_input}],
    )
    return message.content[0].text


# ── VULNERABILITY: Excessive tool permissions — all tools granted to all users ─
TOOL_DEFINITIONS = [
    {"name": "read_file", "description": "Read any file on the server"},
    {"name": "execute_query", "description": "Execute any database query"},
    {"name": "send_email", "description": "Send email to any address"},
    {"name": "delete_record", "description": "Delete any record from any table"},
    {"name": "admin_reset", "description": "Reset any user account"},
    {"name": "transfer_funds", "description": "Transfer money between accounts"},
    {"name": "export_data", "description": "Export all customer data"},
]


def get_tools_for_user(_user_id: str) -> list:
    """Returns ALL tools regardless of user role — no RBAC applied."""
    return TOOL_DEFINITIONS


# ── LangChain agent wrapper — detected by aisec repo scanner ─────────────────
# langchain + langchain-openai are optional deps; install separately if running.
try:
    from langchain.agents import AgentExecutor, create_react_agent
    from langchain_openai import ChatOpenAI

    def build_langchain_agent():
        """Build LangChain agent granting ALL tools — no RBAC (REPOSCAN-011)."""
        llm = ChatOpenAI(model="gpt-4", api_key=OPENAI_API_KEY)
        tools = get_tools_for_user("any_user")  # VULNERABILITY: all tools, no filter
        agent = create_react_agent(llm, tools, SYSTEM_PROMPT)
        agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)
        return agent_executor

except ImportError:
    pass
