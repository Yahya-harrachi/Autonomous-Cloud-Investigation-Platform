# app/ai/orchestrator.py
"""
LLM Orchestrator - Handles tool calling and response generation
"""
import logging
import json
import re
from typing import Dict, Any, List, Optional
from datetime import datetime

from app.services.ollama_service import ollama_service
from app.ai.tools import tool_registry, Tool

logger = logging.getLogger(__name__)


class LLMOrchestrator:
    """
    Orchestrates the LLM interaction with tool calling.
    """

    def __init__(self):
        self.model = "llama3.2:3b"

    def _get_system_prompt(self) -> str:
        """Get the system prompt with strict anti-hallucination rules."""
        tools = tool_registry.list_tools()
        tools_description = "\n".join([
            f"- {tool['name']}: {tool['description']}"
            for tool in tools
        ])

        tool_schemas = []
        for tool in tools:
            tool_schemas.append(f"""
{tool['name']}
Parameters: {json.dumps(tool['parameters'], indent=2)}
""")

        return f"""You are ACIP-AI, an AI assistant for the Autonomous Cloud Investigation Platform (ACIP).

## ⚠️ CRITICAL RULES - READ CAREFULLY:
1. **NEVER invent or make up incidents, evidence, or any data.**
2. **ALWAYS use tools to retrieve real data from the database.**
3. **NEVER say "I found" unless a tool actually returned results.**
4. **NEVER show incidents with IDs that don't exist in the tool results.**
5. **If no data is returned, say: "No incidents found matching your criteria."**
6. **If a tool returns an error, say: "I encountered an error retrieving that information."**
7. **If you are not calling a tool, ONLY answer general/conceptual questions
   (e.g. "how does severity scoring work"). NEVER state a specific count,
   ID, name, or timestamp unless it came directly from a tool result.**

## Available Tools:
{tools_description}

## Tool Schemas:
{''.join(tool_schemas)}

## How to call a tool:
When you need to retrieve data, respond with ONLY a tool call in this exact format,
and nothing else:

```tool
{{
  "tool": "tool_name",
  "arguments": {{
    "param1": "value1",
    "param2": "value2"
  }}
}}
```
"""

    # ============================================================
    # ✅ NEW: deterministic intent routing
    # ============================================================

    def _detect_intent(self, message: str) -> Optional[Dict[str, Any]]:
        """
        Deterministic keyword/regex-based intent routing.

        Small local models (llama3.2:3b) do not reliably emit the exact
```tool fenced JSON format on every data-seeking message. When
        they fail to, the old code fell straight through to returning
        the model's raw, unverified prose — which is how it started
        inventing incidents. This routes the clearest, most common
        intents to a real tool call directly, without depending on the
        LLM to decide to call a tool at all. The LLM is only consulted
        for the free-form fallback path, which is itself guarded below
        by _looks_like_unverified_data_claim().
        """
        text = message.lower().strip()

        # --- Stats intent ---
        if 'incident' in text and re.search(r'\b(how many|stats?|statistics|summary|overview)\b', text):
            return {"tool": "get_incident_stats", "arguments": {}}

        # --- Specific incident / evidence by ID ---
        id_match = re.search(
            r'\b(inc-[a-f0-9]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b',
            message,
            re.IGNORECASE
        )
        if id_match:
            if 'evidence' in text:
                return {"tool": "get_incident_evidence", "arguments": {"incident_id": id_match.group(1)}}
            return {"tool": "get_incident", "arguments": {"incident_id": id_match.group(1)}}

        # --- Search / list intent ---
        search_triggers = [
            'show me', 'find', 'list', 'search', 'incidents', 'critical', 'pending',
            'investigating', 'resolved', 'completed', 'latest', 'recent'
        ]
        if 'incident' in text and any(t in text for t in search_triggers):
            arguments: Dict[str, Any] = {}

            severities = [s.upper() for s in ["critical", "high", "medium", "low", "info"] if s in text]
            if severities:
                arguments["severity"] = severities

            statuses = [s for s in ["pending", "investigating", "completed", "resolved"] if s in text]
            if statuses:
                arguments["status"] = statuses

            if re.search(r'\blatest\b|\bmost recent\b|\blast\b', text):
                arguments["limit"] = 1

            # Light topic heuristic — never a source of truth on its own,
            # just narrows the DB query; still 100% real data either way.
            topic_keywords = [
                "iam", "s3", "ec2", "root", "policy", "role", "bucket",
                "security group", "access key", "mfa", "delete", "create"
            ]
            matched_topics = [kw for kw in topic_keywords if kw in text]
            if matched_topics and "search_term" not in arguments:
                arguments["search_term"] = matched_topics[0]

            return {"tool": "search_incidents", "arguments": arguments}

        return None

    def _looks_like_unverified_data_claim(self, text: str) -> bool:
        """
        Heuristic hallucination guard for the free-text fallback path.
        If the model answered directly (no tool call was made — meaning
        the database was never touched) but the text looks like it's
        citing specific incident data — IDs, "Found N incidents",
        invented timestamps — it is almost certainly fabricated. Block
        it instead of letting it reach the user.
        """
        patterns = [
            r'\binc-[a-f0-9]{4,}\b',                    # fabricated incident IDs
            r'\bfound\s+\d+\s+incident',                # "Found 3 incidents"
            r'\b\d+\s+critical\s+incident',
            r'created\s+at\s+\d{1,2}:\d{2}\s*(am|pm)?',  # invented timestamps
        ]
        lowered = text.lower()
        return any(re.search(p, lowered) for p in patterns)

    def process_message(self, message: str, history: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Process a user message and return a response.

        Args:
            message: The user's message
            history: Conversation history

        Returns:
            Dict with response and metadata
        """
        try:
            # ✅ NEW: try deterministic intent routing FIRST. This bypasses
            # the small model's unreliable tool-call formatting entirely
            # for the common, well-defined intents.
            forced_call = self._detect_intent(message)

            if forced_call:
                logger.info(f"🎯 Deterministic intent match: {forced_call['tool']} {forced_call['arguments']}")
                tool_result = self._execute_tool(forced_call["tool"], forced_call["arguments"])
                explanation = self._generate_explanation(forced_call, tool_result, history)

                return {
                    "success": True,
                    "response": explanation,
                    "tool_used": forced_call["tool"],
                    "tool_result": tool_result,
                    "model": self.model
                }

            # Step 1: Send to LLM with system prompt (fallback path)
            messages = [
                {"role": "system", "content": self._get_system_prompt()}
            ]

            # Add conversation history
            messages.extend(history[-5:])  # Keep last 5 messages for context

            # Add current message
            messages.append({"role": "user", "content": message})

            # Get response from Ollama
            result = ollama_service.chat_with_tools(
                messages=messages,
                model=self.model
            )

            if not result.get("success"):
                return {
                    "success": False,
                    "error": result.get("error", "LLM processing failed"),
                    "response": "I'm having trouble processing your request. Please try again."
                }

            response_content = result.get("response", "")

            # Step 2: Check for tool calls
            tool_call = self._extract_tool_call(response_content)

            if tool_call:
                # Step 3: Execute the tool
                tool_result = self._execute_tool(tool_call["tool"], tool_call["arguments"])

                # Step 4: Format the real tool result (deterministic, no LLM)
                explanation = self._generate_explanation(tool_call, tool_result, messages)

                return {
                    "success": True,
                    "response": explanation,
                    "tool_used": tool_call["tool"],
                    "tool_result": tool_result,
                    "model": self.model
                }
            else:
                # ✅ NEW: the model answered directly, without touching the
                # database. If that answer looks like it's citing specific
                # data anyway, it's fabricated — refuse rather than show it.
                if self._looks_like_unverified_data_claim(response_content):
                    logger.warning(f"⚠️ Blocked unverified data claim from LLM: {response_content[:200]}")
                    return {
                        "success": True,
                        "response": (
                            "I can only share incident or evidence data retrieved directly "
                            "from ACIP's database, and I wasn't able to confirm that with a "
                            "lookup just now. Could you rephrase — for example, "
                            "\"show me critical incidents\" or \"how many incidents are pending?\""
                        ),
                        "model": self.model
                    }

                # Safe: genuinely conversational/conceptual answer, no
                # specific data claims detected.
                return {
                    "success": True,
                    "response": response_content,
                    "model": self.model
                }

        except Exception as e:
            logger.error(f"Error processing message: {e}")
            return {
                "success": False,
                "error": str(e),
                "response": f"An error occurred: {str(e)}"
            }

    def _extract_tool_call(self, content: str) -> Optional[Dict[str, Any]]:
        """Extract tool call from the LLM response."""
        try:
            # Primary: exact fenced format
            pattern = r'```tool\s*\n(.*?)\n```'
            match = re.search(pattern, content, re.DOTALL)

            if match:
                tool_data = json.loads(match.group(1))
                if "tool" in tool_data and "arguments" in tool_data:
                    return tool_data

            # ✅ NEW fallback: small models sometimes drop the fence or add
            # stray text around it. Look for any JSON object anywhere in
            # the response that contains both "tool" and "arguments" keys,
            # so a slightly-malformed-but-genuine tool call attempt still
            # gets caught (better than falling through to raw prose).
            brace_match = re.search(
                r'\{[^{}]*"tool"[^{}]*"arguments"[^{}]*\{.*?\}[^{}]*\}',
                content,
                re.DOTALL
            )
            if brace_match:
                tool_data = json.loads(brace_match.group(0))
                if "tool" in tool_data and "arguments" in tool_data:
                    return tool_data

            return None

        except Exception as e:
            logger.error(f"Error extracting tool call: {e}")
            return None

    def _execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool and return the result."""
        tool = tool_registry.get_tool(tool_name)

        if not tool:
            return {
                "success": False,
                "error": f"Unknown tool: {tool_name}"
            }

        try:
            result = tool.handler(**arguments)
            return result

        except Exception as e:
            logger.error(f"Error executing tool {tool_name}: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def _generate_explanation(
        self,
        tool_call: Dict[str, Any],
        tool_result: Dict[str, Any],
        history: List[Dict[str, str]]
    ) -> str:
        """
        Generate a response from tool results.
        ✅ Deterministic — pure formatting over real data, never an LLM
        call. This is what makes tool-based responses hallucination-proof.
        """
        if not tool_result.get("success"):
            return f"I tried to {tool_call['tool']}, but encountered an error: {tool_result.get('error', 'Unknown error')}"

        if tool_call["tool"] == "search_incidents":
            return self._format_incident_search_results(tool_result)
        elif tool_call["tool"] == "get_incident":
            return self._format_incident_details(tool_result)
        elif tool_call["tool"] == "get_incident_stats":
            return self._format_stats(tool_result)
        elif tool_call["tool"] == "get_incident_evidence":
            return self._format_evidence(tool_result)
        else:
            return f"Here are the results from {tool_call['tool']}:\n\n{json.dumps(tool_result, indent=2)}"

    def _format_incident_search_results(self, result: Dict[str, Any]) -> str:
        """Format incident search results."""
        if result.get("count", 0) == 0:
            return "No incidents found matching your criteria."

        incidents = result.get("incidents", [])
        count = result.get("count", 0)

        response = f"Found {count} incident(s):\n\n"

        for i, inc in enumerate(incidents[:10], 1):
            priority_emoji = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🔵"
            }.get(inc.get("priority", ""), "⚪")

            response += f"{i}. {priority_emoji} {inc.get('title', 'Unknown')}\n"
            response += f"   • ID: {inc.get('display_id', inc.get('id', 'N/A'))}\n"
            response += f"   • Status: {inc.get('status', 'N/A')}\n"
            response += f"   • Created: {inc.get('created_at', 'N/A')[:16] if inc.get('created_at') else 'N/A'}\n"

            if inc.get('tags'):
                response += f"   • Tags: {', '.join(inc['tags'][:5])}\n"

            if inc.get('evidence_count', 0) > 0:
                response += f"   • Evidence: {inc['evidence_count']} artifacts\n"

            response += "\n"

        if count > 10:
            response += f"... and {count - 10} more incidents.\n"

        response += "\nWould you like more details on any specific incident?"

        return response

    def _format_incident_details(self, result: Dict[str, Any]) -> str:
        """Format incident details."""
        if not result.get("success"):
            return f"Error retrieving incident: {result.get('error', 'Unknown error')}"

        incident = result.get("incident", {})

        priority_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵"
        }.get(incident.get("priority", ""), "⚪")

        status_emoji = {
            "pending": "⏳",
            "investigating": "🔍",
            "completed": "✅",
            "resolved": "🔒"
        }.get(incident.get("status", ""), "📌")

        response = f"{priority_emoji} {incident.get('title', 'Unknown')}\n\n"
        response += f"ID: {incident.get('display_id', 'N/A')}\n"
        response += f"Status: {status_emoji} {incident.get('status', 'N/A')}\n"
        response += f"Priority: {incident.get('priority', 'N/A')}\n"
        response += f"Created: {incident.get('created_at', 'N/A')}\n\n"

        if incident.get('description'):
            response += f"Description:\n{incident['description']}\n\n"

        if incident.get('tags'):
            response += f"Tags: {', '.join(incident['tags'][:10])}\n\n"

        evidence_summary = incident.get('evidence_summary', {})
        if evidence_summary:
            response += f"Evidence Collected:\n"
            for ev_type, data in evidence_summary.items():
                response += f"  • {ev_type}: {data['completed']}/{data['total']} completed"
                if data['failed'] > 0:
                    response += f" ({data['failed']} failed)"
                response += "\n"

        if incident.get('assigned_to'):
            response += f"\nAssigned To: {incident['assigned_to']}"

        return response

    def _format_stats(self, result: Dict[str, Any]) -> str:
        """Format incident statistics."""
        if not result.get("success"):
            return f"Error retrieving stats: {result.get('error', 'Unknown error')}"

        stats = result.get("stats", {})

        response = "📊 Incident Statistics\n\n"
        response += f"Total Incidents: {stats.get('total', 0)}\n\n"

        response += "By Status:\n"
        response += f"  ⏳ Pending: {stats.get('pending', 0)}\n"
        response += f"  🔍 Investigating: {stats.get('investigating', 0)}\n"
        response += f"  ✅ Completed: {stats.get('completed', 0)}\n"
        response += f"  🔒 Resolved: {stats.get('resolved', 0)}\n\n"

        by_priority = stats.get('by_priority', {})
        response += "By Priority:\n"
        response += f"  🔴 Critical: {by_priority.get('critical', 0)}\n"
        response += f"  🟠 High: {by_priority.get('high', 0)}\n"
        response += f"  🟡 Medium: {by_priority.get('medium', 0)}\n"
        response += f"  🔵 Low: {by_priority.get('low', 0)}\n"

        return response

    def _format_evidence(self, result: Dict[str, Any]) -> str:
        """Format evidence results from real data only."""
        if not result.get("success"):
            return f"❌ Error retrieving evidence: {result.get('error', 'Unknown error')}"

        total = result.get('total_evidence', 0)
        if total == 0:
            return f"📋 No evidence found for incident {result.get('display_id', '')}"

        # ✅ FIX: was using markdown **bold** — the frontend renders this
        # with plain whitespace-pre-wrap (no markdown parser), so users
        # were literally seeing "**Evidence for...**" with asterisks.
        # Switched to the same plain-text style as the other formatters.
        response = f"📋 Evidence for {result.get('display_id', '')}\n\n"
        response += f"Total Artifacts: {total}\n\n"

        for i, artifact in enumerate(result.get('evidence', []), 1):
            artifact_type = artifact.get('artifact_type', 'Unknown')
            status = artifact.get('collection_status', 'Unknown')
            status_emoji = '✅' if status == 'COMPLETED' else '⚠️' if status == 'PARTIAL' else '❌'

            response += f"{i}. {artifact_type} {status_emoji}\n"
            response += f"   • Source: {artifact.get('source', 'N/A')}\n"
            response += f"   • Collector: {artifact.get('collector', 'N/A')}\n"
            response += f"   • Collected: {artifact.get('collected_at', 'N/A')[:16] if artifact.get('collected_at') else 'N/A'}\n"

            summary = artifact.get('summary', {})

            if artifact_type == 'CloudTrailEvent':
                response += f"   • Events: {summary.get('total_events', 0)} | Timeline: {summary.get('timeline_events', 0)} events\n"
                timeline = artifact.get('timeline_preview', [])
                if timeline:
                    response += f"   • Timeline preview:\n"
                    for event in timeline[:3]:
                        response += f"     - {event.get('time', 'N/A')} - {event.get('event', 'Unknown')} by {event.get('actor', 'Unknown')}\n"

            elif artifact_type == 'IAMUser':
                response += f"   • User: {summary.get('user_name', 'N/A')}\n"
                response += f"   • MFA: {'✅ Enabled' if summary.get('mfa_active') else '❌ Disabled'}\n"
                response += f"   • Policies: {summary.get('attached_policies', 0)} | Access Keys: {summary.get('access_keys', 0)}\n"

            elif artifact_type == 'IAMPolicy':
                response += f"   • Total Policies: {summary.get('total_policies', 0)}\n"
                response += f"   • High Risk: {summary.get('high_risk_findings', 0)}\n"
                policies = summary.get('policies', [])
                if policies:
                    response += f"   • Policies:\n"
                    for policy in policies[:3]:
                        admin = '🔴 (Admin)' if policy.get('admin_access') else ''
                        response += f"     - {policy.get('name', 'Unknown')} {admin}\n"

            elif artifact_type == 'IAMRole':
                response += f"   • Total Roles: {summary.get('total_roles', 0)}\n"
                roles = summary.get('roles', [])
                if roles:
                    response += f"   • Roles: {', '.join(roles[:3])}\n"

            hash_val = artifact.get('hash', '')
            if hash_val:
                response += f"   • SHA-256: {hash_val[:20]}...\n"

            response += "\n"

        return response


# Singleton instance
llm_orchestrator = LLMOrchestrator()
