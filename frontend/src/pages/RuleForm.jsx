import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ruleAPI } from '../services/api';
import {
  RULE_TYPES,
  getRuleTypeOptions,
  getDefaultValues,
  buildCondition,
} from '../config/ruleTypes';

const RuleForm = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const isEdit = !!id;

  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [selectedType, setSelectedType] = useState('event_type');

  const [formData, setFormData] = useState({
    name: '',
    description: '',
    enabled: true,
    priority: 100,
    rule_type: 'event_type',
    condition: { conditions: [], logic: 'and' },
    base_score: 20,
    modifier: 1.0,
    parameters: {},
  });

  useEffect(() => {
    if (isEdit) {
      loadRule();
    }
  }, [id]);

  useEffect(() => {
  // Only reset defaults if we're creating a new rule (not editing)
  if (!isEdit) {
    const defaults = getDefaultValues(selectedType);
    setFormData((prev) => ({
      ...prev,
      rule_type: selectedType,
      base_score: defaults.base_score || 0,
      modifier: defaults.modifier || 1.0,
      parameters: { ...defaults },
    }));
  }
}, [selectedType, isEdit]);

  const loadRule = async () => {
  try {
    setLoading(true);
    const data = await ruleAPI.getById(id);
    
    // ✅ Set selected type first
    setSelectedType(data.rule_type || 'event_type');
    
    // ✅ Build parameters from the rule data
    // If the rule has parameters, use them; otherwise build from condition
    let parameters = data.parameters || {};
    
    // If parameters is empty but we have a condition, try to extract values
    if (Object.keys(parameters).length === 0 && data.condition) {
      const condition = data.condition;
      const conds = condition.conditions || [];
      
      // Try to extract values from conditions based on rule type
      if (data.rule_type === 'context') {
        // Look for hour conditions
        const hourConditions = conds.filter(c => c.field === 'hour');
        if (hourConditions.length === 2) {
          // Find the gte and lt values
          const gte = hourConditions.find(c => c.operator === 'gte');
          const lt = hourConditions.find(c => c.operator === 'lt');
          if (gte && lt) {
            parameters.start_time = `${String(gte.value).padStart(2, '0')}:00`;
            parameters.end_time = `${String(lt.value).padStart(2, '0')}:00`;
          }
        }
        // Look for day_of_week conditions
        const dayCondition = conds.find(c => c.field === 'day_of_week' && c.operator === 'in');
        if (dayCondition) {
          parameters.days = dayCondition.value;
        }
        // Check for public_ip
        const publicIpCondition = conds.find(c => c.field === 'actor_ip' && c.operator === 'is_public');
        if (publicIpCondition) {
          parameters.context_type = 'public_ip';
        }
        // Check for read_only
        const readOnlyCondition = conds.find(c => c.field === 'is_read_only' && c.operator === 'eq' && c.value === true);
        if (readOnlyCondition) {
          parameters.context_type = 'read_only';
        }
        // Check for weekend
        const weekendCondition = conds.find(c => c.field === 'day_of_week' && c.operator === 'in' && c.value && c.value.includes('saturday'));
        if (weekendCondition) {
          parameters.context_type = 'weekend';
        }
        // Default context type
        if (!parameters.context_type) {
          parameters.context_type = 'off_hours';
        }
      } else if (data.rule_type === 'event_type') {
        const eventNameCond = conds.find(c => c.field === 'event_name' && c.operator === 'eq');
        if (eventNameCond) {
          parameters.event_name = eventNameCond.value;
        }
      } else if (data.rule_type === 'identity') {
        const identityTypeCond = conds.find(c => c.field === 'identity_type' && c.operator === 'eq');
        if (identityTypeCond) {
          parameters.identity_type = identityTypeCond.value;
        }
        const actorCond = conds.find(c => c.field === 'actor' && c.operator === 'in');
        if (actorCond && actorCond.value && actorCond.value.length > 0) {
          parameters.identity_names = actorCond.value.join(', ');
        }
      } else if (data.rule_type === 'threat_intel') {
        const confidenceCond = conds.find(c => c.field === 'threat_intel_confidence' && c.operator === 'gte');
        if (confidenceCond) {
          parameters.min_confidence = confidenceCond.value;
        }
        const providerCond = conds.find(c => c.field === 'threat_intel_provider' && c.operator === 'eq');
        if (providerCond) {
          parameters.provider = providerCond.value;
        }
      }
    }
    
    setFormData({
      name: data.name || '',
      description: data.description || '',
      enabled: data.enabled !== undefined ? data.enabled : true,
      priority: data.priority || 100,
      rule_type: data.rule_type || 'event_type',
      condition: data.condition || { conditions: [], logic: 'and' },
      base_score: data.base_score || 0,
      modifier: data.modifier || 1.0,
      parameters: parameters,
    });
    
  } catch (err) {
    console.error('Error loading rule:', err);
    setError('Failed to load rule');
  } finally {
    setLoading(false);
  }
};

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }));
  };

  const handleParameterChange = (key, value) => {
    setFormData((prev) => ({
      ...prev,
      parameters: {
        ...prev.parameters,
        [key]: value,
      },
    }));
  };

  const renderConfigFields = () => {
    const config = RULE_TYPES[selectedType];
    if (!config) return null;

    return config.fields.map((field) => {
      if (field.show_when) {
        const show = Object.keys(field.show_when).every(
          (key) => formData.parameters[key] === field.show_when[key]
        );
        if (!show) return null;
      }

      const value = formData.parameters[field.name] !== undefined
        ? formData.parameters[field.name]
        : field.defaultValue || '';

      switch (field.type) {
        case 'select':
          return (
            <div key={field.name} className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                {field.label}
                {field.required && <span className="text-red-500 ml-1">*</span>}
              </label>
              <select
                value={value}
                onChange={(e) => handleParameterChange(field.name, e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                {field.options.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
              {field.help && <p className="mt-1 text-xs text-gray-500">{field.help}</p>}
            </div>
          );

        case 'time':
          return (
            <div key={field.name} className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                {field.label}
              </label>
              <input
                type="time"
                value={value}
                onChange={(e) => handleParameterChange(field.name, e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              {field.help && <p className="mt-1 text-xs text-gray-500">{field.help}</p>}
            </div>
          );

        case 'multi_select':
          return (
            <div key={field.name} className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                {field.label}
              </label>
              <div className="flex flex-wrap gap-3">
                {field.options.map((opt) => (
                  <label key={opt.value} className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={(value || []).includes(opt.value)}
                      onChange={(e) => {
                        const current = value || [];
                        if (e.target.checked) {
                          handleParameterChange(field.name, [...current, opt.value]);
                        } else {
                          handleParameterChange(field.name, current.filter((v) => v !== opt.value));
                        }
                      }}
                      className="h-4 w-4 text-blue-600 rounded"
                    />
                    <span className="text-sm">{opt.label}</span>
                  </label>
                ))}
              </div>
              {field.help && <p className="mt-1 text-xs text-gray-500">{field.help}</p>}
            </div>
          );

        case 'textarea':
          return (
            <div key={field.name} className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                {field.label}
              </label>
              <textarea
                value={value}
                onChange={(e) => handleParameterChange(field.name, e.target.value)}
                rows={field.rows || 4}
                placeholder={field.placeholder}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
              />
              {field.help && <p className="mt-1 text-xs text-gray-500">{field.help}</p>}
            </div>
          );

        default:
          return (
            <div key={field.name} className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                {field.label}
                {field.required && <span className="text-red-500 ml-1">*</span>}
              </label>
              <input
                type={field.type}
                value={value}
                onChange={(e) => {
                  const val = field.type === 'number'
                    ? parseFloat(e.target.value)
                    : e.target.value;
                  handleParameterChange(field.name, val);
                }}
                placeholder={field.placeholder}
                min={field.min}
                max={field.max}
                step={field.step}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              {field.help && <p className="mt-1 text-xs text-gray-500">{field.help}</p>}
            </div>
          );
      }
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      setSaving(true);
      setError(null);

      const builtCondition = buildCondition(selectedType, formData);

      if (!builtCondition.conditions || builtCondition.conditions.length === 0) {
        setError('Rule must have at least one condition. Please configure the rule properly.');
        setSaving(false);
        return;
      }

      const submitData = {
        ...formData,
        condition: builtCondition,
      };

      if (isEdit) {
        await ruleAPI.update(id, submitData);
      } else {
        await ruleAPI.create(submitData);
      }
      navigate('/rules');
    } catch (err) {
      console.error('Error saving rule:', err);
      setError(err.response?.data?.detail || 'Failed to save rule');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return <div className="text-center py-8">Loading rule...</div>;
  }

  const typeOptions = getRuleTypeOptions();

  return (
    <div className="container mx-auto px-4 py-8 max-w-3xl">
      <h1 className="text-3xl font-bold mb-6">
        {isEdit ? 'Edit Rule' : 'Create New Rule'}
      </h1>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-6">
          <strong>Error:</strong> {error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="bg-white rounded-lg shadow p-6">
        {/* Basic Info */}
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Rule Name *
            </label>
            <input
              type="text"
              name="name"
              value={formData.name}
              onChange={handleChange}
              required
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="e.g., DeleteTrail Detection"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Description
            </label>
            <textarea
              name="description"
              value={formData.description}
              onChange={handleChange}
              rows="2"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Describe what this rule does..."
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Rule Type *
              </label>
              <select
                value={selectedType}
                onChange={(e) => setSelectedType(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                {typeOptions.map((type) => (
                  <option key={type.value} value={type.value}>
                    {type.icon} {type.label}
                  </option>
                ))}
              </select>
              <p className="mt-1 text-xs text-gray-500">
                {RULE_TYPES[selectedType]?.description}
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Priority (lower = higher)
              </label>
              <input
                type="number"
                name="priority"
                value={formData.priority}
                onChange={handleChange}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                min="1"
              />
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <input
              type="checkbox"
              name="enabled"
              checked={formData.enabled}
              onChange={handleChange}
              id="enabled"
              className="h-4 w-4 text-blue-600 rounded"
            />
            <label htmlFor="enabled" className="text-sm font-medium text-gray-700">
              Enabled
            </label>
          </div>
        </div>

        {/* Rule Type Specific Configuration */}
        <div className="mt-6 border-t border-gray-200 pt-6">
          <h3 className="text-lg font-medium mb-4">
            {RULE_TYPES[selectedType]?.icon} {RULE_TYPES[selectedType]?.label} Configuration
          </h3>
          {renderConfigFields()}

          {/* Base Score & Modifier */}
          <div className="grid grid-cols-2 gap-4 mt-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Base Score
              </label>
              <input
                type="number"
                name="base_score"
                value={formData.base_score}
                onChange={handleChange}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                min="0"
                max="100"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Modifier
              </label>
              <input
                type="number"
                name="modifier"
                value={formData.modifier}
                onChange={handleChange}
                step="0.1"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                min="0.1"
                max="3.0"
              />
            </div>
          </div>
        </div>

        {/* Form Actions */}
        <div className="mt-6 border-t border-gray-200 pt-6 flex justify-end space-x-3">
          <button
            type="button"
            onClick={() => navigate('/rules')}
            className="px-4 py-2 border border-gray-300 rounded-md hover:bg-gray-50"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={saving}
            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
          >
            {saving ? 'Saving...' : isEdit ? 'Update Rule' : 'Create Rule'}
          </button>
        </div>
      </form>
    </div>
  );
};

export default RuleForm;