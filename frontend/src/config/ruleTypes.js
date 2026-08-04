/**
 * Rule Type Configurations - Complete
 * Each type has: label, icon, description, fields, default values, and condition builder
 */
export const RULE_TYPES = {
  event_type: {
    label: 'Event Type',
    icon: '📋',
    description: 'Set base score for specific event types',
    fields: [
      {
        name: 'event_name',
        label: 'Event Name',
        type: 'text',
        placeholder: 'e.g. ConsoleLogin, DeleteTrail',
        required: true,
        help: 'Enter the exact event name from CloudTrail',
      },
      {
        name: 'base_score',
        label: 'Base Score',
        type: 'number',
        placeholder: '0-100',
        min: 0,
        max: 100,
        required: true,
        help: 'Higher score = higher risk',
      },
      {
        name: 'modifier',
        label: 'Modifier',
        type: 'number',
        placeholder: '0.1 - 3.0',
        step: 0.1,
        min: 0.1,
        max: 3.0,
        defaultValue: 1.0,
        help: 'Multiplier for the base score',
      },
    ],
    default_values: { base_score: 20, modifier: 1.0 },
    default_condition: { conditions: [{ field: 'event_name', operator: 'eq', value: '' }], logic: 'and' },
    build_condition: (formData) => ({
      conditions: [{ field: 'event_name', operator: 'eq', value: formData.parameters?.event_name || '' }],
      logic: 'and'
    }),
  },

  identity: {
    label: 'Identity',
    icon: '👤',
    description: 'Set risk modifier based on who performed the action',
    fields: [
      {
        name: 'identity_type',
        label: 'Identity Type',
        type: 'select',
        options: [
          { value: 'root', label: 'Root User' },
          { value: 'assumed_role', label: 'Assumed Role' },
          { value: 'federated_user', label: 'Federated User' },
          { value: 'user', label: 'IAM User' },
          { value: 'service_account', label: 'Service Account' },
        ],
        required: true,
      },
      {
        name: 'identity_names',
        label: 'Specific Identities (Optional)',
        type: 'text',
        placeholder: 'admin, developer, service-account',
        help: 'Comma-separated list. Leave empty to apply to all identities of this type',
      },
      {
        name: 'modifier',
        label: 'Risk Modifier',
        type: 'number',
        placeholder: '0.1 - 3.0',
        step: 0.1,
        min: 0.1,
        max: 3.0,
        required: true,
        help: 'Higher value = higher risk',
      },
    ],
    default_values: { base_score: 0, modifier: 1.0, identity_names: '' },
    default_condition: { conditions: [{ field: 'identity_type', operator: 'eq', value: '' }], logic: 'and' },
    build_condition: (formData) => {
      const conditions = [{ field: 'identity_type', operator: 'eq', value: formData.parameters?.identity_type || '' }];
      if (formData.parameters?.identity_names) {
        const names = formData.parameters.identity_names.split(',').map(s => s.trim()).filter(Boolean);
        if (names.length > 0) {
          conditions.push({ field: 'actor', operator: 'in', value: names });
        }
      }
      return { conditions, logic: 'and' };
    },
  },

  context: {
    label: 'Context',
    icon: '🌐',
    description: 'Set risk modifier based on event context',
    fields: [
      {
        name: 'context_type',
        label: 'Context Type',
        type: 'select',
        options: [
          { value: 'off_hours', label: 'Off-Hours Activity' },
          { value: 'public_ip', label: 'Public IP Address' },
          { value: 'read_only', label: 'Read-Only Operation' },
          { value: 'new_region', label: 'New/Unusual Region' },
          { value: 'weekend', label: 'Weekend Activity' },
          { value: 'custom', label: 'Custom Context' },
        ],
        required: true,
      },
      // Off-Hours fields
      {
        name: 'start_time',
        label: 'Start Time',
        type: 'time',
        defaultValue: '22:00',
        help: 'Time when off-hours begins',
        show_when: { context_type: 'off_hours' },
      },
      {
        name: 'end_time',
        label: 'End Time',
        type: 'time',
        defaultValue: '06:00',
        help: 'Time when off-hours ends',
        show_when: { context_type: 'off_hours' },
      },
      {
        name: 'days',
        label: 'Days of Week',
        type: 'multi_select',
        options: [
          { value: 'monday', label: 'Mon' },
          { value: 'tuesday', label: 'Tue' },
          { value: 'wednesday', label: 'Wed' },
          { value: 'thursday', label: 'Thu' },
          { value: 'friday', label: 'Fri' },
          { value: 'saturday', label: 'Sat' },
          { value: 'sunday', label: 'Sun' },
        ],
        defaultValue: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'],
        help: 'Select days when off-hours applies',
        show_when: { context_type: 'off_hours' },
      },
      // Public IP fields
      {
        name: 'exclude_ranges',
        label: 'Exclude IP Ranges (Optional)',
        type: 'text',
        placeholder: 'e.g. 10.0.0.0/8, 172.16.0.0/12',
        help: 'Comma-separated list of IP ranges to exclude',
        show_when: { context_type: 'public_ip' },
      },
      {
        name: 'include_only',
        label: 'Include Only Specific IP Ranges (Optional)',
        type: 'text',
        placeholder: 'e.g. 8.0.0.0/8, 4.0.0.0/8',
        help: 'Leave empty to apply to all public IPs',
        show_when: { context_type: 'public_ip' },
      },
      // New Region fields
      {
        name: 'trusted_regions',
        label: 'Trusted Regions (Exclude)',
        type: 'text',
        placeholder: 'us-east-1, us-west-2, eu-west-1',
        defaultValue: 'us-east-1, us-west-2, eu-west-1',
        help: 'Comma-separated list of trusted regions',
        show_when: { context_type: 'new_region' },
      },
      {
        name: 'monitor_regions',
        label: 'Monitor Specific Regions (Optional)',
        type: 'text',
        placeholder: 'ap-southeast-1, sa-east-1',
        help: 'Comma-separated list. Leave empty to monitor all except trusted',
        show_when: { context_type: 'new_region' },
      },
      // Modifier
      {
        name: 'modifier',
        label: 'Risk Modifier',
        type: 'number',
        placeholder: '0.1 - 3.0',
        step: 0.1,
        min: 0.1,
        max: 3.0,
        required: true,
        help: 'Higher value = higher risk when context matches',
      },
    ],
    default_values: {
      base_score: 0,
      modifier: 1.0,
      context_type: 'off_hours',
      start_time: '22:00',
      end_time: '06:00',
      days: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'],
      exclude_ranges: '',
      include_only: '',
      trusted_regions: 'us-east-1, us-west-2, eu-west-1',
      monitor_regions: '',
    },
    default_condition: {
      conditions: [
        { field: 'hour', operator: 'gte', value: 22 },
        { field: 'hour', operator: 'lt', value: 6 },
        { field: 'day_of_week', operator: 'in', value: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'] }
      ],
      logic: 'and'
    },
    build_condition: (formData) => {
      const params = formData.parameters || {};
      const contextType = params.context_type || 'off_hours';
      const conditions = [];

      switch (contextType) {
        case 'off_hours': {
          const startTime = params.start_time || '22:00';
          const endTime = params.end_time || '06:00';
          const days = params.days || ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'];

          const startHour = parseInt(startTime.split(':')[0]);
          const endHour = parseInt(endTime.split(':')[0]);

          // Off-hours: hour is between startHour and endHour (e.g., 22:00 - 06:00)
          conditions.push({ field: 'hour', operator: 'gte', value: startHour });
          conditions.push({ field: 'hour', operator: 'lt', value: endHour });

          if (days && days.length > 0) {
            conditions.push({ field: 'day_of_week', operator: 'in', value: days });
          }
          break;
        }
        case 'public_ip': {
          conditions.push({ field: 'actor_ip', operator: 'is_public', value: true });
          // Add exclude ranges if provided
          if (params.exclude_ranges) {
            const ranges = params.exclude_ranges.split(',').map(s => s.trim()).filter(Boolean);
            if (ranges.length > 0) {
              conditions.push({ field: 'actor_ip', operator: 'not_in_range', value: ranges });
            }
          }
          // Add include only ranges if provided
          if (params.include_only) {
            const ranges = params.include_only.split(',').map(s => s.trim()).filter(Boolean);
            if (ranges.length > 0) {
              conditions.push({ field: 'actor_ip', operator: 'in_range', value: ranges });
            }
          }
          break;
        }
        case 'read_only': {
          conditions.push({ field: 'is_read_only', operator: 'eq', value: true });
          break;
        }
        case 'weekend': {
          conditions.push({ field: 'day_of_week', operator: 'in', value: ['saturday', 'sunday'] });
          break;
        }
        case 'new_region': {
          const trusted = params.trusted_regions ? params.trusted_regions.split(',').map(s => s.trim()).filter(Boolean) : ['us-east-1', 'us-west-2', 'eu-west-1'];
          const monitor = params.monitor_regions ? params.monitor_regions.split(',').map(s => s.trim()).filter(Boolean) : [];

          if (monitor.length > 0) {
            conditions.push({ field: 'region', operator: 'in', value: monitor });
          } else if (trusted.length > 0) {
            conditions.push({ field: 'region', operator: 'not_in', value: trusted });
          }
          break;
        }
        default: {
          conditions.push({ field: 'context_type', operator: 'eq', value: contextType });
        }
      }

      return { conditions, logic: 'and' };
    },
  },

  threat_intel: {
    label: 'Threat Intelligence',
    icon: '🛡️',
    description: 'Set risk modifier based on threat intelligence results',
    fields: [
      {
        name: 'provider',
        label: 'Threat Intel Provider',
        type: 'select',
        options: [
          { value: 'abuseipdb', label: 'AbuseIPDB' },
          { value: 'virustotal', label: 'VirusTotal' },
          { value: 'any', label: 'Any Provider' },
        ],
        defaultValue: 'abuseipdb',
        required: true,
      },
      {
        name: 'min_confidence',
        label: 'Minimum Confidence Score',
        type: 'number',
        placeholder: '0-100',
        min: 0,
        max: 100,
        defaultValue: 50,
        required: true,
        help: 'Only apply rule when confidence is above this threshold',
      },
      {
        name: 'categories',
        label: 'Threat Categories (Optional)',
        type: 'multi_select',
        options: [
          { value: 'malware', label: 'Malware' },
          { value: 'phishing', label: 'Phishing' },
          { value: 'port_scanning', label: 'Port Scanning' },
          { value: 'web_attack', label: 'Web Attack' },
          { value: 'brute_force', label: 'Brute Force' },
          { value: 'ddos', label: 'DDoS' },
          { value: 'c2', label: 'Command & Control' },
        ],
        help: 'Leave empty to apply to all threat categories',
      },
      {
        name: 'modifier',
        label: 'Risk Modifier',
        type: 'number',
        placeholder: '0.1 - 3.0',
        step: 0.1,
        min: 0.1,
        max: 3.0,
        required: true,
        help: 'Higher value = higher risk for threats',
      },
    ],
    default_values: {
      base_score: 0,
      modifier: 2.0,
      provider: 'abuseipdb',
      min_confidence: 50,
      categories: [],
    },
    default_condition: {
      conditions: [{ field: 'threat_intel_confidence', operator: 'gte', value: 50 }],
      logic: 'and'
    },
    build_condition: (formData) => {
      const params = formData.parameters || {};
      const conditions = [
        { field: 'threat_intel_confidence', operator: 'gte', value: params.min_confidence || 50 }
      ];
      if (params.provider && params.provider !== 'any') {
        conditions.push({ field: 'threat_intel_provider', operator: 'eq', value: params.provider });
      }
      if (params.categories && params.categories.length > 0) {
        conditions.push({ field: 'threat_intel_categories', operator: 'overlaps', value: params.categories });
      }
      return { conditions, logic: 'and' };
    },
  },

  custom: {
    label: 'Custom (Advanced)',
    icon: '⚡',
    description: 'Build custom rules with advanced conditions',
    fields: [
      {
        name: 'condition_json',
        label: 'Conditions (JSON format)',
        type: 'textarea',
        rows: 8,
        placeholder: '{"conditions": [{"field": "event_name", "operator": "eq", "value": "ConsoleLogin"}], "logic": "and"}',
        help: 'Enter conditions in JSON format',
      },
      {
        name: 'base_score',
        label: 'Base Score',
        type: 'number',
        placeholder: '0-100',
        min: 0,
        max: 100,
        defaultValue: 0,
      },
      {
        name: 'modifier',
        label: 'Modifier',
        type: 'number',
        placeholder: '0.1 - 3.0',
        step: 0.1,
        min: 0.1,
        max: 3.0,
        defaultValue: 1.0,
      },
    ],
    default_values: {
      base_score: 0,
      modifier: 1.0,
      condition_json: '{"conditions": [{"field": "event_name", "operator": "eq", "value": ""}], "logic": "and"}',
    },
    default_condition: { conditions: [], logic: 'and' },
    build_condition: (formData) => {
      try {
        return JSON.parse(formData.parameters?.condition_json || '{"conditions": [], "logic": "and"}');
      } catch {
        return { conditions: [], logic: 'and' };
      }
    },
  },
};

export const getRuleTypeOptions = () => {
  return Object.keys(RULE_TYPES).map(key => ({
    value: key,
    label: RULE_TYPES[key].label,
    icon: RULE_TYPES[key].icon,
    description: RULE_TYPES[key].description,
  }));
};

export const getRuleTypeConfig = (type) => {
  return RULE_TYPES[type] || RULE_TYPES.event_type;
};

export const getDefaultCondition = (type) => {
  const config = getRuleTypeConfig(type);
  return config.default_condition || { conditions: [], logic: 'and' };
};

export const getDefaultValues = (type) => {
  const config = getRuleTypeConfig(type);
  return config.default_values || { base_score: 0, modifier: 1.0 };
};

export const buildCondition = (type, formData) => {
  const config = getRuleTypeConfig(type);
  if (config.build_condition) {
    return config.build_condition(formData);
  }
  return config.default_condition || { conditions: [], logic: 'and' };
};