# app/services/pdf_generator.py
"""
PDF Report Generator - Generates professional PDF reports for incidents
"""
import os
import logging
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path
import json

from weasyprint import HTML, CSS
from jinja2 import Template
import markdown

logger = logging.getLogger(__name__)


class PDFReportGenerator:
    """
    Generates professional PDF reports for incidents with evidence.
    """
    
    def __init__(self):
        self.template_dir = Path(__file__).parent.parent / "templates"
        self.template_dir.mkdir(exist_ok=True)
    
    def generate_incident_report(self, incident_data: Dict[str, Any], evidence_data: List[Dict[str, Any]]) -> bytes:
        """
        Generate a PDF report for an incident.
        
        Args:
            incident_data: The incident data
            evidence_data: List of evidence artifacts
            
        Returns:
            PDF bytes
        """
        # Prepare data for template with safe defaults
        report_data = self._prepare_report_data(incident_data, evidence_data)
        
        # Generate HTML from template
        html_content = self._render_template(report_data)
        
        # Convert HTML to PDF
        pdf_bytes = self._html_to_pdf(html_content)
        
        return pdf_bytes
    
    def _prepare_report_data(self, incident: Dict[str, Any], evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare data for the report template with safe defaults."""
        # Ensure incident has all required fields
        safe_incident = {
            "id": incident.get('id', 'N/A'),
            "title": incident.get('title', 'N/A'),
            "description": incident.get('description', 'No description provided'),
            "status": incident.get('status', 'N/A'),
            "priority": incident.get('priority', 'N/A'),
            "source_type": incident.get('source_type', 'N/A'),
            "source_event_id": incident.get('source_event_id', 'N/A'),
            "tags": incident.get('tags', []),
            "assigned_to": incident.get('assigned_to'),
            "assigned_team": incident.get('assigned_team'),
            "evidence_count": incident.get('evidence_count', 0),
            "created_at": incident.get('created_at', 'N/A'),
            "updated_at": incident.get('updated_at', 'N/A'),
            "resolved_at": incident.get('resolved_at', 'N/A'),
            "extra_data": incident.get('extra_data', {})
        }
        
        # Ensure evidence is a list
        safe_evidence = evidence if evidence else []
        
        # Generate summary with safe defaults
        summary = self._generate_summary(safe_incident, safe_evidence)
        
        return {
            "incident": safe_incident,
            "evidence": safe_evidence,
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "total_evidence": len(safe_evidence),
            "summary": summary
        }
    
    def _generate_summary(self, incident: Dict[str, Any], evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a summary of the incident and evidence."""
        summary = {
            "critical_findings": [],
            "security_issues": [],
            "evidence_types": {}
        }
        
        # Extract security findings from evidence
        for artifact in evidence:
            artifact_type = artifact.get('artifact_type', 'Unknown')
            summary["evidence_types"][artifact_type] = summary["evidence_types"].get(artifact_type, 0) + 1
            
            # Extract findings from different artifact types
            content = artifact.get('content', {})
            
            if artifact_type == 'IAMPolicy':
                findings = content.get('security_analysis', {})
                high_risk = findings.get('high_risk_findings', [])
                for finding in high_risk:
                    summary["critical_findings"].append({
                        "type": "IAM Policy",
                        "description": finding.get('description', 'Unknown finding'),
                        "recommendation": finding.get('recommendation', 'No recommendation')
                    })
            
            elif artifact_type == 'CloudTrailEvent':
                patterns = content.get('patterns', [])
                for pattern in patterns:
                    if pattern.get('severity') in ['high', 'critical']:
                        summary["security_issues"].append({
                            "type": "Attack Pattern",
                            "description": pattern.get('description', 'Unknown pattern'),
                            "recommendation": pattern.get('recommendation', 'No recommendation')
                        })
        
        return summary
    
    def _render_template(self, data: Dict[str, Any]) -> str:
        """Render the HTML template with data."""
        template_str = self._get_template()
        template = Template(template_str)
        return template.render(**data)
    
    def _get_template(self) -> str:
        """Get the HTML template for the report."""
        return """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ACIP Incident Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
            font-size: 12px;
            line-height: 1.6;
            color: #1a202c;
            padding: 40px;
            background: #ffffff;
        }
        .report-container { max-width: 900px; margin: 0 auto; }
        .header {
            border-bottom: 3px solid #3182ce;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 { font-size: 28px; color: #2b6cb0; font-weight: 700; }
        .header .subtitle { color: #718096; font-size: 14px; margin-top: 5px; }
        .header .meta {
            display: flex;
            justify-content: space-between;
            margin-top: 10px;
            font-size: 12px;
            color: #718096;
        }
        .section { margin-bottom: 30px; }
        .section-title {
            font-size: 18px;
            font-weight: 600;
            color: #2d3748;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 8px;
            margin-bottom: 15px;
        }
        .incident-info {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            background: #f7fafc;
            padding: 15px;
            border-radius: 8px;
        }
        .info-item {
            display: flex;
            flex-direction: column;
        }
        .info-item .label {
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #718096;
        }
        .info-item .value {
            font-size: 14px;
            color: #2d3748;
            margin-top: 3px;
            word-break: break-word;
        }
        .priority-badge {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }
        .priority-critical { background: #fed7d7; color: #c53030; }
        .priority-high { background: #feebc8; color: #c05621; }
        .priority-medium { background: #fefcbf; color: #975a16; }
        .priority-low { background: #bee3f8; color: #2a69ac; }
        .status-badge {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }
        .status-pending { background: #fefcbf; color: #975a16; }
        .status-investigating { background: #bee3f8; color: #2a69ac; }
        .status-completed { background: #c6f6d5; color: #276749; }
        .status-resolved { background: #e9d8fd; color: #553c9a; }
        .description-box {
            background: #f7fafc;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #3182ce;
        }
        .tags {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-top: 10px;
        }
        .tag {
            background: #edf2f7;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 11px;
            color: #4a5568;
        }
        .evidence-card {
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
        }
        .evidence-header {
            background: #f7fafc;
            padding: 12px 15px;
            border-bottom: 1px solid #e2e8f0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .evidence-header .type { font-weight: 600; color: #2d3748; }
        .evidence-header .status {
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 10px;
            background: #c6f6d5;
            color: #276749;
        }
        .evidence-body { padding: 15px; }
        .finding-critical { background: #fed7d7; border-left: 3px solid #c53030; }
        .finding-high { background: #feebc8; border-left: 3px solid #c05621; }
        .finding-medium { background: #fefcbf; border-left: 3px solid #975a16; }
        .finding-low { background: #bee3f8; border-left: 3px solid #2a69ac; }
        .finding {
            padding: 10px 12px;
            border-radius: 4px;
            margin-bottom: 8px;
        }
        .finding .severity { font-weight: 600; font-size: 11px; }
        .finding .description { margin-top: 3px; }
        .finding .recommendation {
            margin-top: 5px;
            font-size: 11px;
            color: #4a5568;
            font-style: italic;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }
        .summary-box {
            background: #f7fafc;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }
        .summary-box .number {
            font-size: 28px;
            font-weight: 700;
            color: #2b6cb0;
        }
        .summary-box .label {
            font-size: 11px;
            color: #718096;
            margin-top: 5px;
        }
        .timeline-item {
            display: flex;
            align-items: flex-start;
            padding: 8px 0;
            border-bottom: 1px solid #edf2f7;
        }
        .timeline-item:last-child { border-bottom: none; }
        .timeline-time {
            min-width: 100px;
            font-size: 11px;
            color: #718096;
            font-family: monospace;
        }
        .timeline-event { font-size: 12px; }
        .timeline-event .event-name { font-weight: 500; }
        .timeline-event .event-actor { color: #718096; }
        .timeline-trigger { color: #c53030; font-weight: 600; }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e2e8f0;
            font-size: 11px;
            color: #718096;
            text-align: center;
        }
        @media print {
            body { padding: 20px; }
            .evidence-card { break-inside: avoid; }
            .summary-grid { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="report-container">
        <!-- Header -->
        <div class="header">
            <h1>🔍 ACIP Incident Report</h1>
            <div class="subtitle">Autonomous Cloud Investigation Platform</div>
            <div class="meta">
                <span>Generated: {{ generated_at }}</span>
                <span>Report ID: {{ incident.id }}</span>
            </div>
        </div>

        <!-- Summary -->
        <div class="section">
            <div class="summary-grid">
                <div class="summary-box">
                    <div class="number">{{ total_evidence }}</div>
                    <div class="label">Evidence Artifacts</div>
                </div>
                <div class="summary-box">
                    <div class="number">{{ summary.evidence_types|length }}</div>
                    <div class="label">Evidence Types</div>
                </div>
                <div class="summary-box">
                    <div class="number">{{ summary.critical_findings|length + summary.security_issues|length }}</div>
                    <div class="label">Security Findings</div>
                </div>
            </div>
        </div>

        <!-- Incident Details -->
        <div class="section">
            <h2 class="section-title">📋 Incident Details</h2>
            
            <div class="incident-info">
                <div class="info-item">
                    <span class="label">Title</span>
                    <span class="value">{{ incident.title }}</span>
                </div>
                <div class="info-item">
                    <span class="label">ID</span>
                    <span class="value" style="font-family: monospace;">{{ incident.id }}</span>
                </div>
                <div class="info-item">
                    <span class="label">Priority</span>
                    <span class="priority-badge priority-{{ incident.priority|lower }}">{{ incident.priority }}</span>
                </div>
                <div class="info-item">
                    <span class="label">Status</span>
                    <span class="status-badge status-{{ incident.status|lower }}">{{ incident.status }}</span>
                </div>
                <div class="info-item">
                    <span class="label">Source Type</span>
                    <span class="value">{{ incident.source_type }}</span>
                </div>
                <div class="info-item">
                    <span class="label">Created At</span>
                    <span class="value">{{ incident.created_at }}</span>
                </div>
                {% if incident.assigned_to %}
                <div class="info-item">
                    <span class="label">Assigned To</span>
                    <span class="value">{{ incident.assigned_to }}</span>
                </div>
                {% endif %}
            </div>

            <!-- Description -->
            <div style="margin-top: 15px;">
                <div class="label" style="font-weight: 600; margin-bottom: 5px;">Description</div>
                <div class="description-box">{{ incident.description }}</div>
            </div>

            <!-- Tags -->
            {% if incident.tags %}
            <div class="tags">
                {% for tag in incident.tags %}
                <span class="tag">#{{ tag }}</span>
                {% endfor %}
            </div>
            {% endif %}
        </div>

        <!-- Critical Findings -->
        {% if summary.critical_findings %}
        <div class="section">
            <h2 class="section-title">🚨 Critical Findings</h2>
            {% for finding in summary.critical_findings %}
            <div class="finding finding-critical">
                <div class="severity">🔴 CRITICAL</div>
                <div class="description">{{ finding.description }}</div>
                <div class="recommendation">💡 {{ finding.recommendation }}</div>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        <!-- Security Issues -->
        {% if summary.security_issues %}
        <div class="section">
            <h2 class="section-title">⚠️ Security Issues</h2>
            {% for issue in summary.security_issues %}
            <div class="finding finding-high">
                <div class="severity">🟠 HIGH</div>
                <div class="description">{{ issue.description }}</div>
                <div class="recommendation">💡 {{ issue.recommendation }}</div>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        <!-- Evidence -->
        <div class="section">
            <h2 class="section-title">📊 Evidence ({{ total_evidence }})</h2>
            
            {% for artifact in evidence %}
            <div class="evidence-card">
                <div class="evidence-header">
                    <span class="type">📦 {{ artifact.artifact_type }}</span>
                    <span class="status">{{ artifact.collection_status }}</span>
                </div>
                <div class="evidence-body">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 5px; font-size: 11px; margin-bottom: 10px;">
                        <div><strong>Source:</strong> {{ artifact.source }}</div>
                        <div><strong>Collector:</strong> {{ artifact.collector }}</div>
                        <div><strong>Collected:</strong> {{ artifact.collected_at }}</div>
                        <div><strong>Hash:</strong> <span style="font-family: monospace;">{{ artifact.hash[:20] if artifact.hash else 'N/A' }}...</span></div>
                    </div>
                    
                    <!-- CloudTrail Timeline -->
                    {% if artifact.artifact_type == 'CloudTrailEvent' and artifact.content and artifact.content.timeline %}
                    <div style="margin-top: 10px;">
                        <div style="font-weight: 600; font-size: 12px; margin-bottom: 5px;">🕐 Timeline</div>
                        {% for event in artifact.content.timeline[:10] %}
                        <div class="timeline-item">
                            <span class="timeline-time">{{ event.event_time[:19] if event.event_time else 'N/A' }}</span>
                            <div class="timeline-event">
                                <span class="event-name {% if event.is_trigger %}timeline-trigger{% endif %}">
                                    {% if event.is_trigger %}🚨 {% endif %}{{ event.event_name }}
                                </span>
                                <span class="event-actor">by {{ event.actor or 'Unknown' }}</span>
                            </div>
                        </div>
                        {% endfor %}
                        {% if artifact.content.timeline|length > 10 %}
                        <div style="font-size: 11px; color: #718096; padding-top: 5px;">
                            + {{ artifact.content.timeline|length - 10 }} more events
                        </div>
                        {% endif %}
                    </div>
                    {% endif %}
                    
                    <!-- IAM User Details -->
                    {% if artifact.artifact_type == 'IAMUser' and artifact.content and artifact.content.user %}
                    <div style="margin-top: 10px;">
                        <div style="font-weight: 600; font-size: 12px; margin-bottom: 5px;">👤 User Details</div>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 5px; font-size: 11px;">
                            <div><strong>Username:</strong> {{ artifact.content.user.user_name }}</div>
                            <div><strong>MFA:</strong> {{ '✅ Enabled' if artifact.content.user.mfa_active else '❌ Disabled' }}</div>
                            <div><strong>Policies:</strong> {{ artifact.content.summary.total_attached_policies if artifact.content.summary else 0 }}</div>
                            <div><strong>Access Keys:</strong> {{ artifact.content.summary.total_access_keys if artifact.content.summary else 0 }}</div>
                        </div>
                    </div>
                    {% endif %}
                    
                    <!-- IAM Policy Details -->
                    {% if artifact.artifact_type == 'IAMPolicy' and artifact.content and artifact.content.policies %}
                    <div style="margin-top: 10px;">
                        <div style="font-weight: 600; font-size: 12px; margin-bottom: 5px;">📋 Policies</div>
                        {% for policy in artifact.content.policies[:3] %}
                        <div style="font-size: 11px; padding: 5px; background: #f7fafc; border-radius: 4px; margin-bottom: 5px;">
                            <strong>{{ policy.policy_name }}</strong>
                            <span style="color: #718096; display: block; font-family: monospace; font-size: 10px;">{{ policy.arn }}</span>
                            {% if policy.summary and policy.summary.has_administrator_access %}
                            <span style="color: #c53030; font-weight: 600;">🔴 Admin Access</span>
                            {% endif %}
                        </div>
                        {% endfor %}
                        {% if artifact.content.policies|length > 3 %}
                        <div style="font-size: 11px; color: #718096;">+ {{ artifact.content.policies|length - 3 }} more policies</div>
                        {% endif %}
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>This report was automatically generated by ACIP - Autonomous Cloud Investigation Platform</p>
            <p>© {{ generated_at[:4] }} ACIP. All rights reserved.</p>
            <p style="margin-top: 5px;">Confidential - For authorized security personnel only</p>
        </div>
    </div>
</body>
</html>
        """
    
    def _html_to_pdf(self, html_content: str) -> bytes:
        """Convert HTML content to PDF."""
        try:
            # Use WeasyPrint to generate PDF
            html = HTML(string=html_content, base_url="")
            pdf_bytes = html.write_pdf()
            return pdf_bytes
        except Exception as e:
            logger.error(f"Error generating PDF: {e}")
            # Fallback: try with simpler settings
            try:
                html = HTML(string=html_content)
                pdf_bytes = html.write_pdf()
                return pdf_bytes
            except Exception as e2:
                logger.error(f"PDF generation fallback failed: {e2}")
                raise