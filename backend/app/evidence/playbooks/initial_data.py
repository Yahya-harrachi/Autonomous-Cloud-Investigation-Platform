# app/evidence/playbooks/initial_data.py
from app.domain.models.evidence import EvidencePlaybook

INITIAL_PLAYBOOKS = [
    {
        "name": "IAM_PRIVILEGE_ESCALATION",
        "description": "Investigates IAM privilege escalation attempts",
        "trigger_events": [
            "AttachUserPolicy",
            "AttachRolePolicy", 
            "PutUserPolicy",
            "PutRolePolicy",
            "CreateAccessKey",
            "UpdateAssumeRolePolicy"
        ],
        "evidence_required": [
            "CloudTrailEvent",
            "IAMUser",
            "IAMPolicy",
            "IAMRole"
        ],
        "enabled": True,
        "version": "1.0.0"
    },
    {
        "name": "S3_EXPOSURE",
        "description": "Investigates potential S3 bucket exposure",
        "trigger_events": [
            "PutBucketPolicy",
            "PutBucketAcl",
            "PutBucketPublicAccessBlock",
            "DeleteBucketPublicAccessBlock"
        ],
        "evidence_required": [
            "CloudTrailEvent",
            "S3Bucket",
            "S3Policy"
        ],
        "enabled": True,
        "version": "1.0.0"
    },
    {
        "name": "SECURITY_GROUP_EXPOSURE",
        "description": "Investigates security group exposure",
        "trigger_events": [
            "AuthorizeSecurityGroupIngress",
            "AuthorizeSecurityGroupEgress",
            "RevokeSecurityGroupIngress"
        ],
        "evidence_required": [
            "CloudTrailEvent",
            "SecurityGroup",
            "EC2Instance"
        ],
        "enabled": True,
        "version": "1.0.0"
    }
]

def seed_playbooks(db_session):
    """Insert initial playbooks into database"""
    for playbook_data in INITIAL_PLAYBOOKS:
        existing = db_session.query(EvidencePlaybook).filter(
            EvidencePlaybook.name == playbook_data["name"]
        ).first()
        
        if not existing:
            playbook = EvidencePlaybook(**playbook_data)
            db_session.add(playbook)
    
    db_session.commit()