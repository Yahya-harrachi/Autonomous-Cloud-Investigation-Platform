import React, { useState, useEffect } from 'react';
import { ruleAPI } from '../services/api';

const RuleList = () => {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadRules();
  }, []);

  const loadRules = async () => {
    try {
      const data = await ruleAPI.getAll();
      setRules(data || []);
    } catch (err) {
      console.error('Error loading rules:', err);
    } finally {
      setLoading(false);
    }
  };

  const toggleRule = async (id, currentStatus) => {
    try {
      if (currentStatus) {
        await ruleAPI.disable(id);
      } else {
        await ruleAPI.enable(id);
      }
      await loadRules();
    } catch (err) {
      console.error('Error toggling rule:', err);
    }
  };

  const deleteRule = async (id) => {
    if (!window.confirm('Delete this rule?')) return;
    try {
      await ruleAPI.delete(id);
      await loadRules();
    } catch (err) {
      console.error('Error deleting rule:', err);
    }
  };

  if (loading) {
    return <div className="text-center py-8">Loading rules...</div>;
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold">Risk Rules</h1>
        <a href="/rules/new" className="bg-blue-600 text-white px-4 py-2 rounded-md">
          + New Rule
        </a>
      </div>

      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Base Score</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Modifier</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {rules.length === 0 ? (
              <tr>
                <td colSpan="6" className="px-6 py-8 text-center text-gray-500">
                  No rules found. Create your first rule!
                </td>
              </tr>
            ) : (
              rules.map((rule) => (
                <tr key={rule.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <button
                      onClick={() => toggleRule(rule.id, rule.enabled)}
                      className={`px-2 py-1 rounded text-xs ${
                        rule.enabled
                          ? 'bg-green-100 text-green-800'
                          : 'bg-gray-200 text-gray-600'
                      }`}
                    >
                      {rule.enabled ? '✅ Active' : '❌ Disabled'}
                    </button>
                  </td>
                  <td className="px-6 py-4">{rule.name}</td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 text-xs rounded-full ${
                      rule.rule_type === 'event_type' ? 'bg-blue-100 text-blue-800' :
                      rule.rule_type === 'identity' ? 'bg-purple-100 text-purple-800' :
                      rule.rule_type === 'context' ? 'bg-yellow-100 text-yellow-800' :
                      rule.rule_type === 'threat_intel' ? 'bg-red-100 text-red-800' :
                      'bg-gray-100 text-gray-800'
                    }`}>
                      {rule.rule_type}
                    </span>
                  </td>
                  <td className="px-6 py-4">{rule.base_score}</td>
                  <td className="px-6 py-4">{rule.modifier}x</td>
                  <td className="px-6 py-4 space-x-2">
                    <a href={`/rules/${rule.id}/edit`} className="text-blue-600 hover:text-blue-800">
                      ✏️
                    </a>
                    <button onClick={() => deleteRule(rule.id)} className="text-red-600 hover:text-red-800">
                      🗑️
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default RuleList;