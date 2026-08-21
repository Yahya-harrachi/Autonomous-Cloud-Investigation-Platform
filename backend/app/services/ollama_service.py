
"""
Ollama Service - Handles communication with local Ollama LLM
"""
import logging
import json
import httpx
from typing import Optional, Dict, Any, List
from datetime import datetime

from app.core.config import settings

logger = logging.getLogger(__name__)


class OllamaService:
    """
    Service for communicating with local Ollama LLM.
    """
    
    def __init__(self):
        self.base_url = "http://localhost:11434"
        self.model = "llama3.2:3b"
        self.timeout = 120.0  # Increased for complex reasoning
        self.client = httpx.Client(timeout=self.timeout)
        
    def _get_system_prompt(self) -> str:
        """Get the system prompt for the AI assistant."""
        return """You are ACIP-AI, an AI assistant for the Autonomous Cloud Investigation Platform.
You help SOC analysts investigate security incidents in AWS cloud environments.

Your capabilities:
- Answer questions about cloud security incidents
- Help analysts understand security events
- Provide guidance on investigation steps
- Explain security concepts

You are currently in basic mode and cannot access the database yet.
You can only have general conversations about cloud security.

When asked about specific incidents, explain that you need to be connected to the ACIP system to access incident data.

Be professional, concise, and helpful. Focus on cloud security and incident investigation.
"""
    
    def chat(self, message: str, conversation_history: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
        """
        Send a chat message to Ollama and get a response.
        
        Args:
            message: The user's message
            conversation_history: Previous messages in the conversation
            
        Returns:
            Dict with the response and metadata
        """
        try:
            # Prepare messages
            messages = []
            
            # Add system prompt
            messages.append({
                "role": "system",
                "content": self._get_system_prompt()
            })
            
            # Add conversation history
            if conversation_history:
                messages.extend(conversation_history)
            
            # Add current message
            messages.append({
                "role": "user",
                "content": message
            })
            
            # Prepare request
            request_data = {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "top_p": 0.9,
                    "num_predict": 512
                }
            }
            
            # Send to Ollama
            response = self.client.post(
                f"{self.base_url}/api/chat",
                json=request_data
            )
            
            if response.status_code != 200:
                logger.error(f"Ollama API error: {response.status_code} - {response.text}")
                return {
                    "success": False,
                    "error": f"Ollama API error: {response.status_code}",
                    "response": "I'm having trouble connecting to my AI service. Please try again."
                }
            
            result = response.json()
            ai_response = result.get("message", {}).get("content", "")
            
            return {
                "success": True,
                "response": ai_response,
                "model": self.model,
                "tokens": result.get("eval_count", 0)
            }
            
        except httpx.TimeoutException:
            logger.error("Ollama request timed out")
            return {
                "success": False,
                "error": "Request timed out",
                "response": "The AI service is taking too long to respond. Please try again."
            }
        except Exception as e:
            logger.error(f"Error in Ollama chat: {e}")
            return {
                "success": False,
                "error": str(e),
                "response": "An error occurred while processing your request."
            }
    
    def chat_with_tools(self, messages: List[Dict[str, str]], model: Optional[str] = None) -> Dict[str, Any]:
        """
        Chat with Ollama specifically for tool-based interactions.
        
        Args:
            messages: The full message history including system prompt
            model: The model to use (defaults to self.model)
            
        Returns:
            Dict with the response and metadata
        """
        try:
            request_data = {
                "model": model or self.model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": 0.3,  # Lower temperature for consistent tool calls
                    "top_p": 0.9,
                    "num_predict": 1024  # Higher for complex responses
                }
            }
            
            response = self.client.post(
                f"{self.base_url}/api/chat",
                json=request_data
            )
            
            if response.status_code != 200:
                logger.error(f"Ollama API error (tools): {response.status_code} - {response.text}")
                return {
                    "success": False,
                    "error": f"Ollama API error: {response.status_code}"
                }
            
            result = response.json()
            return {
                "success": True,
                "response": result.get("message", {}).get("content", ""),
                "model": result.get("model", model or self.model),
                "tokens": result.get("eval_count", 0)
            }
            
        except httpx.TimeoutException:
            logger.error("Ollama request timed out (tools)")
            return {
                "success": False,
                "error": "Request timed out"
            }
        except Exception as e:
            logger.error(f"Error in Ollama chat_with_tools: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def is_available(self) -> bool:
        """Check if Ollama is available."""
        try:
            response = self.client.get(f"{self.base_url}/api/tags", timeout=5.0)
            return response.status_code == 200
        except Exception:
            return False
    
    def list_models(self) -> List[str]:
        """Get list of available models."""
        try:
            response = self.client.get(f"{self.base_url}/api/tags")
            if response.status_code == 200:
                data = response.json()
                return [model["name"] for model in data.get("models", [])]
            return []
        except Exception:
            return []


# Singleton instance
ollama_service = OllamaService()