// frontend/src/pages/AIAssistant.jsx
import React, { useState, useRef, useEffect } from 'react';
import api from '../services/api';

const AIAssistant = () => {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [conversationId, setConversationId] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [modelInfo, setModelInfo] = useState(null);
  const [error, setError] = useState(null);
  const messagesEndRef = useRef(null);

  // Auto-scroll to bottom of messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Check AI service health on mount
  useEffect(() => {
    checkHealth();
  }, []);

  const checkHealth = async () => {
    try {
      const response = await api.get('/ai/health');
      setIsConnected(response.data.status === 'available');
      setModelInfo({
        model: response.data.active_model || 'llama3.2:3b',
        models: response.data.models || []
      });
    } catch (err) {
      console.error('AI service unavailable:', err);
      setIsConnected(false);
      setError('AI service is not available. Please ensure Ollama is running.');
    }
  };

  // Welcome message
  useEffect(() => {
    if (isConnected) {
      setMessages([
        {
          role: 'assistant',
          content: `👋 Hello! I'm ACIP-AI, your cloud investigation assistant.

I can help you:
• 🔍 Search and investigate security incidents
• 📊 Analyze evidence and timelines
• 🛡️ Understand risk scores and severity
• 📋 Summarize incident findings
• 🔗 Find similar incidents

Currently running: **${modelInfo?.model || 'Llama 3.2 3B'}**

What would you like to investigate today?`,
          timestamp: new Date().toISOString()
        }
      ]);
    }
  }, [isConnected, modelInfo]);

  const sendMessage = async () => {
    if (!input.trim() || loading || !isConnected) return;

    const userMessage = input.trim();
    setInput('');
    setError(null);

    // Add user message to chat
    setMessages(prev => [...prev, {
      role: 'user',
      content: userMessage,
      timestamp: new Date().toISOString()
    }]);

    setLoading(true);

    try {
      // Prepare conversation history (last 10 messages for context)
      const history = messages
        .slice(-10)
        .map(msg => ({
          role: msg.role,
          content: msg.content
        }));

      // Send to backend
      const response = await api.post('/ai/chat', {
        message: userMessage,
        conversation_id: conversationId,
        history: history
      });

      const data = response.data;

      // Save conversation ID
      if (data.conversation_id) {
        setConversationId(data.conversation_id);
      }

      // Add AI response
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: data.response,
        timestamp: data.timestamp,
        model: data.model,
        tokens: data.tokens
      }]);

    } catch (err) {
      console.error('Error sending message:', err);
      setError(err.response?.data?.detail || 'Failed to get response from AI');
      
      // Add error message
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: `❌ I'm sorry, I encountered an error: ${err.response?.data?.detail || 'Please try again.'}`,
        timestamp: new Date().toISOString(),
        isError: true
      }]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const clearConversation = () => {
    setMessages([
      {
        role: 'assistant',
        content: '🔄 Conversation cleared. How can I help you?',
        timestamp: new Date().toISOString()
      }
    ]);
    setConversationId(null);
  };

  const suggestedQuestions = [
    "Show me critical incidents from today",
    "What's the latest incident?",
    "How many incidents are pending?",
    "Show me IAM-related incidents",
    "Explain how severity scoring works",
    "What evidence is collected for incidents?"
  ];

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">🤖 AI Assistant</h1>
            <p className="text-sm text-gray-500 mt-1">
              Natural language investigation interface for ACIP
            </p>
          </div>
          <div className="flex items-center space-x-4">
            {/* Connection Status */}
            <div className="flex items-center space-x-2">
              <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className="text-sm text-gray-600">
                {isConnected ? `Connected (${modelInfo?.model || 'LLM'})` : 'Disconnected'}
              </span>
            </div>
            {!isConnected && (
              <button
                onClick={checkHealth}
                className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
              >
                Reconnect
              </button>
            )}
            <button
              onClick={clearConversation}
              className="px-3 py-1 text-sm bg-gray-200 text-gray-700 rounded hover:bg-gray-300"
            >
              Clear Chat
            </button>
          </div>
        </div>
      </div>

      {/* AI Service Unavailable */}
      {!isConnected && (
        <div className="mb-4 bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <div className="flex items-start">
            <span className="text-2xl mr-3">⚠️</span>
            <div>
              <h3 className="font-medium text-yellow-800">AI Service Unavailable</h3>
              <p className="text-sm text-yellow-700 mt-1">
                The AI service is not connected. Please ensure Ollama is running with Llama 3.2 3B.
              </p>
              <div className="mt-2 text-xs text-yellow-600 font-mono">
                Run: <code className="bg-yellow-100 px-2 py-1 rounded">ollama serve</code> and <code className="bg-yellow-100 px-2 py-1 rounded">ollama pull llama3.2:3b</code>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Chat Container */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        {/* Messages */}
        <div className="h-[500px] overflow-y-auto p-4 space-y-4">
          {messages.map((msg, idx) => (
            <div
              key={idx}
              className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-[75%] rounded-lg px-4 py-3 ${
                  msg.role === 'user'
                    ? 'bg-blue-600 text-white'
                    : msg.isError
                    ? 'bg-red-50 text-red-700 border border-red-200'
                    : 'bg-gray-100 text-gray-800'
                }`}
              >
                <div className="whitespace-pre-wrap text-sm leading-relaxed">{msg.content}</div>
                <div className={`text-xs mt-1 ${msg.role === 'user' ? 'text-blue-200' : 'text-gray-400'}`}>
                  {msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString() : ''}
                  {msg.model && ` • ${msg.model}`}
                  {msg.tokens && ` • ${msg.tokens} tokens`}
                </div>
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex justify-start">
              <div className="bg-gray-100 text-gray-800 rounded-lg px-4 py-3 max-w-[75%]">
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce"></div>
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.4s' }}></div>
                </div>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Suggested Questions */}
        {messages.length < 3 && isConnected && (
          <div className="px-4 pb-3 border-t border-gray-100 pt-3">
            <p className="text-xs text-gray-400 mb-2">Try asking:</p>
            <div className="flex flex-wrap gap-2">
              {suggestedQuestions.map((q, idx) => (
                <button
                  key={idx}
                  onClick={() => {
                    setInput(q);
                    setTimeout(() => sendMessage(), 100);
                  }}
                  className="px-3 py-1 text-xs bg-gray-50 border border-gray-200 rounded-full hover:bg-gray-100 text-gray-600 transition-colors"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="px-4 pb-2">
            <div className="text-sm text-red-600 bg-red-50 p-2 rounded">
              ❌ {error}
            </div>
          </div>
        )}

        {/* Input */}
        <div className="px-4 py-3 border-t border-gray-200 bg-gray-50">
          <div className="flex items-end space-x-2">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder={isConnected ? "Ask about incidents, evidence, or security..." : "AI service unavailable..."}
              rows={2}
              className="flex-1 resize-none border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:bg-gray-100 disabled:cursor-not-allowed"
              disabled={loading || !isConnected}
            />
            <button
              onClick={sendMessage}
              disabled={loading || !input.trim() || !isConnected}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? '...' : 'Send'}
            </button>
          </div>
          <div className="mt-1 text-xs text-gray-400 flex justify-between">
            <span>Press Enter to send, Shift+Enter for new line</span>
            <span>{input.length} characters</span>
          </div>
        </div>
      </div>

      {/* Footer Info */}
      <div className="mt-4 text-xs text-gray-400 text-center">
        <p>ACIP-AI uses Llama 3.2 3B running locally via Ollama. All processing is done on your machine.</p>
        <p className="mt-1">Version 1.0.0 - Phase 1: Local AI Foundation</p>
      </div>
    </div>
  );
};

export default AIAssistant;