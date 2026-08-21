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
        """Get the system prompt with tool descriptions."""
        tools = tool_registry.list_tools()
        tools_description = "\n".join([
            f"- {tool['name']}: {tool['description']}"
            f"  Parameters: {json.dumps(tool['parameters'], indent=2)}"
            for tool in tools
        ])

        return f"""You are ACIP-AI, an AI assistant for the Autonomous Cloud Investigation Platform (ACIP).

You help SOC analysts investigate security incidents in AWS cloud environments.

## Your Capabilities:
You have access to the following tools to retrieve information:
{tools_description}

## How to Use Tools:
When a user asks a question that requires data, you should:
1. Identify which tool can answer the question
2. Respond with a structured tool call in this exact format:
```tool
{{
  "tool": "tool_name",
  "arguments": {{
    "arg1": "value1",
    "arg2": "value2"
  }}
}}
```
3. After receiving the tool result, explain it to the user in natural language.

## Important Rules:
- You are a READ-ONLY assistant. You cannot modify incidents, evidence, or AWS resources.
- Only use the tools listed above. Do not invent tools.
- If you don't know something, say so. Do not make up information.
- Distinguish between facts (what actually happened) and interpretations (what it might mean).
- Be concise and professional. Focus on security investigation.

## Example Conversation:
User: "Show me critical incidents from today"
You:
```tool
{{
  "tool": "search_incidents",
  "arguments": {{
    "severity": ["CRITICAL"],
    "date_from": "2026-08-21T00:00:00Z"
  }}
}}
```
Then after getting results:
"I found 3 critical incidents from today:
1. [CRITICAL] DeleteUser by admin - Created at 10:23 AM
2. [CRITICAL] AttachUserPolicy by yahya-harrachi - Created at 11:45 AM
3. [CRITICAL] CreateAccessKey by root - Created at 2:15 PM

The most recent is the CreateAccessKey by root. Would you like details on any specific incident?"

Current time: {datetime.utcnow().isoformat()}
"""

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
            # Step 1: Send to LLM with system prompt
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

                # Step 4: Send tool result back to LLM for explanation
                explanation = self._generate_explanation(tool_call, tool_result, messages)

                return {
                    "success": True,
                    "response": explanation,
                    "tool_used": tool_call["tool"],
                    "tool_result": tool_result,
                    "model": self.model
                }
            else:
                # No tool call, return the response directly
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
            # Look for tool call pattern: ```tool ... ```
            pattern = r'```tool\s*\n(.*?)\n```'
            match = re.search(pattern, content, re.DOTALL)

            if match:
                tool_data = json.loads(match.group(1))
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
            # Validate arguments
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
        """Generate a natural language explanation of tool results."""

        # If tool execution failed
        if not tool_result.get("success"):
            return f"I tried to {tool_call['tool']}, but encountered an error: {tool_result.get('error', 'Unknown error')}"

        # Format results based on tool type
        if tool_call["tool"] == "search_incidents":
            return self._format_incident_search_results(tool_result)
        elif tool_call["tool"] == "get_incident":
            return self._format_incident_details(tool_result)
        elif tool_call["tool"] == "get_incident_stats":
            return self._format_stats(tool_result)
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

        # Description
        if incident.get('description'):
            response += f"Description:\n{incident['description']}\n\n"

        # Tags
        if incident.get('tags'):
            response += f"Tags: {', '.join(incident['tags'][:10])}\n\n"

        # Evidence summary
        evidence_summary = incident.get('evidence_summary', {})
        if evidence_summary:
            response += f"Evidence Collected:\n"
            for ev_type, data in evidence_summary.items():
                response += f"  • {ev_type}: {data['completed']}/{data['total']} completed"
                if data['failed'] > 0:
                    response += f" ({data['failed']} failed)"
                response += "\n"

        # Assignment
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

        # By status
        response += "By Status:\n"
        response += f"  ⏳ Pending: {stats.get('pending', 0)}\n"
        response += f"  🔍 Investigating: {stats.get('investigating', 0)}\n"
        response += f"  ✅ Completed: {stats.get('completed', 0)}\n"
        response += f"  🔒 Resolved: {stats.get('resolved', 0)}\n\n"

        # By priority
        by_priority = stats.get('by_priority', {})
        response += "By Priority:\n"
        response += f"  🔴 Critical: {by_priority.get('critical', 0)}\n"
        response += f"  🟠 High: {by_priority.get('high', 0)}\n"
        response += f"  🟡 Medium: {by_priority.get('medium', 0)}\n"
        response += f"  🔵 Low: {by_priority.get('low', 0)}\n"

        return response


# Singleton instance
llm_orchestrator = LLMOrchestrator()