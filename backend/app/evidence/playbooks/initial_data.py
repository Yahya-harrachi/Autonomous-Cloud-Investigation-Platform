# app/evidence/playbooks/initial_data.py
"""
Initial playbook data for evidence collection
"""
from app.models.evidence import EvidencePlaybook
from app.core.database import SessionLocal


INITIAL_PLAYBOOKS = [
    {
        "name": "IAM_PRIVILEGE_ESCALATION",
        "description": "Investigates IAM privilege escalation attempts including policy attachments and role changes",
        "trigger_events": [
            "AttachUserPolicy",
            "AttachRolePolicy",
            "PutUserPolicy",
            "PutRolePolicy",
            "CreateAccessKey",
            "UpdateAssumeRolePolicy",
            "DeleteUserPolicy",
            "DetachUserPolicy"
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
        "description": "Investigates potential S3 bucket exposure through policy or ACL changes",
        "trigger_events": [
            "PutBucketPolicy",
            "PutBucketAcl",
            "PutBucketPublicAccessBlock",
            "DeleteBucketPublicAccessBlock",
            "PutBucketWebsite"
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
        "description": "Investigates security group changes that may expose resources",
        "trigger_events": [
            "AuthorizeSecurityGroupIngress",
            "AuthorizeSecurityGroupEgress",
            "RevokeSecurityGroupIngress",
            "RevokeSecurityGroupEgress"
        ],
        "evidence_required": [
            "CloudTrailEvent",
            "SecurityGroup",
            "EC2Instance"
        ],
        "enabled": True,
        "version": "1.0.0"
    },
    {
        "name": "ROOT_ACTIVITY",
        "description": "Investigates root user activity which should be rare and monitored",
        "trigger_events": [
            "ConsoleLogin",
            "CreateUser",
            "DeleteUser",
            "CreateAccessKey",
            "DeleteAccessKey"
        ],
        "evidence_required": [
            "CloudTrailEvent",
            "IAMUser"
        ],
        "enabled": True,
        "version": "1.0.0"
    }
]


def seed_playbooks():
    """Insert initial playbooks into database if they don't exist"""
    db = SessionLocal()
    try:
        for playbook_data in INITIAL_PLAYBOOKS:
            # Check if playbook already exists
            existing = db.query(EvidencePlaybook).filter(
                EvidencePlaybook.name == playbook_data["name"]
            ).first()
            
            if not existing:
                playbook = EvidencePlaybook(**playbook_data)
                db.add(playbook)
                print(f"✅ Added playbook: {playbook_data['name']}")
            else:
                print(f"⏭️ Playbook already exists: {playbook_data['name']}")
        
        db.commit()
        print("✅ All playbooks seeded successfully!")
        
    except Exception as e:
        print(f"❌ Error seeding playbooks: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    seed_playbooks()