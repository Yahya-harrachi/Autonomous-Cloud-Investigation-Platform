// frontend/src/components/ai/AIChat.jsx
import React, { useState, useRef, useEffect } from 'react';
import api from '../../services/api';

const AIChat = ({ incidentId }) => {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [conversationId, setConversationId] = useState(null);
  const [error, setError] = useState(null);
  const messagesEndRef = useRef(null);

  // Auto-scroll to bottom of messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Welcome message
  useEffect(() => {
    setMessages([
      {
        role: 'assistant',
        content: '👋 Hello! I\'m ACIP-AI, your cloud investigation assistant.\n\nI can help you investigate security incidents, analyze evidence, and understand cloud security events.\n\nWhat would you like to investigate?',
        timestamp: new Date().toISOString()
      }
    ]);
  }, []);

  const sendMessage = async () => {
    if (!input.trim() || loading) return;

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
        model: data.model
      }]);

    } catch (err) {
      console.error('Error sending message:', err);
      setError(err.response?.data?.detail || 'Failed to get response from AI');
      
      // Add error message
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: '❌ I\'m sorry, I encountered an error. Please try again.\n\n' + (err.response?.data?.detail || ''),
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

  return (
    <div className="flex flex-col h-[600px] bg-white rounded-lg shadow-sm border border-gray-200">
      {/* Header */}
      <div className="px-4 py-3 bg-gray-50 border-b border-gray-200 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <span className="text-xl">🤖</span>
          <div>
            <h3 className="font-medium text-gray-900">ACIP-AI Assistant</h3>
            <p className="text-xs text-gray-500">Powered by Llama 3.2 3B</p>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <div className={`w-2 h-2 rounded-full ${loading ? 'bg-yellow-400 animate-pulse' : 'bg-green-500'}`}></div>
          <span className="text-xs text-gray-500">{loading ? 'Thinking...' : 'Ready'}</span>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((msg, idx) => (
          <div
            key={idx}
            className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            <div
              className={`max-w-[80%] rounded-lg px-4 py-3 ${
                msg.role === 'user'
                  ? 'bg-blue-600 text-white'
                  : msg.isError
                  ? 'bg-red-50 text-red-700 border border-red-200'
                  : 'bg-gray-100 text-gray-800'
              }`}
            >
              <div className="whitespace-pre-wrap text-sm">{msg.content}</div>
              <div className={`text-xs mt-1 ${msg.role === 'user' ? 'text-blue-200' : 'text-gray-400'}`}>
                {msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString() : ''}
                {msg.model && ` • ${msg.model}`}
              </div>
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex justify-start">
            <div className="bg-gray-100 text-gray-800 rounded-lg px-4 py-3 max-w-[80%]">
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

      {/* Input */}
      <div className="px-4 py-3 border-t border-gray-200">
        {error && (
          <div className="mb-2 text-sm text-red-600 bg-red-50 p-2 rounded">
            ❌ {error}
          </div>
        )}
        <div className="flex items-center space-x-2">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Ask about incidents, evidence, or security..."
            rows={2}
            className="flex-1 resize-none border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            disabled={loading}
          />
          <button
            onClick={sendMessage}
            disabled={loading || !input.trim()}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? '...' : 'Send'}
          </button>
        </div>
        <div className="mt-1 text-xs text-gray-400">
          Press Enter to send, Shift+Enter for new line
        </div>
      </div>
    </div>
  );
};

export default AIChat;