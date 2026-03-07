"""DPDP Privacy AI Agent - Production Implementation"""

import re
import json
import logging
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path
import base64
from cryptography.fernet import Fernet
import os

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dpdp_agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DataCategory(Enum):
    PII = "Personally Identifiable Information"
    SENSITIVE = "Sensitive Personal Data"
    FINANCIAL = "Financial Data"
    HEALTH = "Health Data"
    GENERAL = "General Data"

class ConsentStatus(Enum):
    GRANTED = "granted"
    REVOKED = "revoked"
    PENDING = "pending"

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class DataItem:
    content: str
    category: DataCategory
    user_id: str
    created_at: datetime
    retention_days: int = 365

@dataclass
class ConsentRecord:
    user_id: str
    purpose: str
    status: ConsentStatus
    granted_at: datetime
    expires_at: Optional[datetime] = None

@dataclass
class AuditLog:
    timestamp: datetime
    user_id: str
    action: str
    data_category: str
    result: str

class DPDPAgent:
    def __init__(self, storage_path: str = "data/dpdp_storage.json", encryption_key: Optional[str] = None):
        self.compiled_patterns = {
            DataCategory.PII: [re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), 
                              re.compile(r'\b\d{10}\b'), re.compile(r'\b\d{12}\b')],
            DataCategory.FINANCIAL: [re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b')],
            DataCategory.HEALTH: [re.compile(r'\b(diabetes|hypertension|cancer|HIV)\b', re.IGNORECASE)],
        }
        self.consents: Dict[str, List[ConsentRecord]] = {}
        self.data_store: Dict[str, List[DataItem]] = {}
        self.audit_logs: List[AuditLog] = []
        self.breach_threshold = 5
        self.max_audit_logs = 1000
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Setup encryption
        key = encryption_key or os.environ.get('DPDP_ENCRYPTION_KEY')
        if key:
            self.cipher = Fernet(key.encode() if len(key) == 44 else base64.urlsafe_b64encode(key.encode().ljust(32)[:32]))
        else:
            # Generate key if not provided (save this!)
            self.cipher = Fernet(Fernet.generate_key())
            logger.warning("No encryption key provided, generated new key. Save this for data recovery!")
        
        self._load_state()
        logger.info("DPDPAgent initialized")
    
    def _encrypt(self, data: str) -> str:
        """Encrypt sensitive data"""
        return self.cipher.encrypt(data.encode()).decode()
    
    def _decrypt(self, data: str) -> str:
        """Decrypt sensitive data"""
        return self.cipher.decrypt(data.encode()).decode()
    
    def _load_state(self):
        """Load persisted state from disk"""
        try:
            if self.storage_path.exists():
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                    
                    # Load consents
                    for user_id, consents in data.get('consents', {}).items():
                        self.consents[user_id] = [
                            ConsentRecord(
                                c['user_id'], c['purpose'], 
                                ConsentStatus(c['status']),
                                datetime.fromisoformat(c['granted_at']),
                                datetime.fromisoformat(c['expires_at']) if c.get('expires_at') else None
                            ) for c in consents
                        ]
                    
                    # Load data store
                    for user_id, items in data.get('data_store', {}).items():
                        self.data_store[user_id] = [
                            DataItem(
                                self._decrypt(i['content']),
                                self._parse_category(i['category']),
                                i['user_id'],
                                datetime.fromisoformat(i['created_at']),
                                i['retention_days']
                            ) for i in items
                        ]
                    
                    # Load audit logs
                    for log in data.get('audit_logs', [])[-self.max_audit_logs:]:
                        self.audit_logs.append(
                            AuditLog(
                                datetime.fromisoformat(log['timestamp']),
                                log['user_id'],
                                log['action'],
                                log['data_category'],
                                log['result']
                            )
                        )
                logger.info("State loaded from disk")
        except Exception as e:
            logger.error(f"Failed to load state: {e}")
    
    def _parse_category(self, category_str: str) -> DataCategory:
        """Parse category from string, handling both enum name and value"""
        try:
            # Try direct enum name (e.g., "PII")
            return DataCategory[category_str]
        except KeyError:
            # Try by value (e.g., "Personally Identifiable Information")
            for cat in DataCategory:
                if cat.value == category_str:
                    return cat
            # Fallback
            return DataCategory.GENERAL
    
    def _save_state(self):
        """Persist state to disk with atomic write"""
        try:
            # Prepare data
            data = {
                'consents': {
                    uid: [asdict(c) for c in consents] 
                    for uid, consents in self.consents.items()
                },
                'data_store': {
                    uid: [{
                        'content': self._encrypt(item.content),
                        'category': item.category.name,
                        'user_id': item.user_id,
                        'created_at': item.created_at.isoformat(),
                        'retention_days': item.retention_days
                    } for item in items]
                    for uid, items in self.data_store.items()
                },
                'audit_logs': [asdict(log) for log in self.audit_logs[-self.max_audit_logs:]],
                'last_saved': datetime.now().isoformat()
            }
            
            # Atomic write: write to temp file, then rename
            temp_path = self.storage_path.with_suffix('.tmp')
            with open(temp_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            temp_path.replace(self.storage_path)
            
            # Trim in-memory audit logs
            if len(self.audit_logs) > self.max_audit_logs:
                self.audit_logs = self.audit_logs[-self.max_audit_logs:]
            
            logger.info("State saved to disk")
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
    
    def classify_data(self, text: str) -> DataCategory:
        """Classify data based on content patterns"""
        for category, patterns in self.compiled_patterns.items():
            if any(p.search(text) for p in patterns):
                return category
        return DataCategory.GENERAL
    
    def assess_risk(self, category: DataCategory, has_consent: bool) -> RiskLevel:
        """Assess risk level for data processing"""
        if category == DataCategory.HEALTH and not has_consent:
            return RiskLevel.CRITICAL
        if category in [DataCategory.FINANCIAL, DataCategory.SENSITIVE] and not has_consent:
            return RiskLevel.HIGH
        if category == DataCategory.PII and not has_consent:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
    
    def check_consent(self, user_id: str, purpose: str) -> bool:
        """Verify if user has granted consent for purpose"""
        if user_id not in self.consents:
            return False
        for c in self.consents[user_id]:
            if c.purpose == purpose and c.status == ConsentStatus.GRANTED:
                if c.expires_at and datetime.now() > c.expires_at:
                    c.status = ConsentStatus.REVOKED
                    self._save_state()
                    return False
                return True
        return False
    
    def grant_consent(self, user_id: str, purpose: str, duration_days: Optional[int] = None):
        """Grant user consent for data processing"""
        try:
            if not user_id or not purpose:
                raise ValueError("user_id and purpose are required")
            
            # Validate input length
            if len(user_id) > 255 or len(purpose) > 255:
                raise ValueError("user_id and purpose must be <= 255 characters")
            
            if user_id not in self.consents:
                self.consents[user_id] = []
            
            # Check for duplicate
            for c in self.consents[user_id]:
                if c.purpose == purpose and c.status == ConsentStatus.GRANTED:
                    logger.warning(f"Consent already exists for user {user_id}, purpose: {purpose}")
                    return
            
            expires = datetime.now() + timedelta(days=duration_days) if duration_days else None
            self.consents[user_id].append(
                ConsentRecord(user_id, purpose, ConsentStatus.GRANTED, datetime.now(), expires)
            )
            self._log_action(user_id, "consent_granted", "N/A", f"Purpose: {purpose}")
            self._save_state()
            logger.info(f"Consent granted for user {user_id}, purpose: {purpose}")
        except Exception as e:
            logger.error(f"Failed to grant consent: {e}")
            raise
    
    def revoke_consent(self, user_id: str, purpose: str):
        """Revoke user consent"""
        try:
            if not user_id or not purpose:
                raise ValueError("user_id and purpose are required")
            
            if user_id not in self.consents:
                logger.warning(f"No consents found for user {user_id}")
                return
            
            found = False
            for consent in self.consents[user_id]:
                if consent.purpose == purpose:
                    consent.status = ConsentStatus.REVOKED
                    self._log_action(user_id, "consent_revoked", "N/A", f"Purpose: {purpose}")
                    found = True
            
            if not found:
                logger.warning(f"No consent found for user {user_id}, purpose: {purpose}")
            else:
                self._save_state()
                logger.info(f"Consent revoked for user {user_id}, purpose: {purpose}")
        except Exception as e:
            logger.error(f"Failed to revoke consent: {e}")
            raise
    
    def anonymize(self, text: str) -> str:
        """Anonymize PII in text"""
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 
                     '[EMAIL]', text)
        text = re.sub(r'\b\d{10}\b', '[PHONE]', text)
        text = re.sub(r'\b\d{12}\b', '[AADHAAR]', text)
        text = re.sub(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', 
                     '[CARD]', text)
        return text
    
    def store_data(self, user_id: str, text: str, retention_days: int = 365):
        """Store data with retention policy"""
        try:
            if not user_id or not text:
                raise ValueError("user_id and text are required")
            
            # Validate input length
            if len(user_id) > 255:
                raise ValueError("user_id must be <= 255 characters")
            if len(text) > 100000:
                raise ValueError("text must be <= 100000 characters")
            
            category = self.classify_data(text)
            if user_id not in self.data_store:
                self.data_store[user_id] = []
            item = DataItem(text, category, user_id, datetime.now(), retention_days)
            self.data_store[user_id].append(item)
            self._log_action(user_id, "data_stored", category.value, "success")
            self._save_state()
            logger.info(f"Data stored for user {user_id}, category: {category.value}")
        except Exception as e:
            logger.error(f"Failed to store data: {e}")
            raise
    
    def delete_expired_data(self) -> int:
        """Delete data past retention period"""
        try:
            deleted = 0
            for user_id, items in self.data_store.items():
                expired = [i for i in items if 
                          datetime.now() > i.created_at + timedelta(days=i.retention_days)]
                deleted += len(expired)
                self.data_store[user_id] = [i for i in items if i not in expired]
            logger.info(f"Deleted {deleted} expired data items")
            return deleted
        except Exception as e:
            logger.error(f"Failed to delete expired data: {e}")
            return 0
    
    def right_to_erasure(self, user_id: str):
        """Delete all user data (Right to be forgotten)"""
        try:
            count = 0
            if user_id in self.data_store:
                count = len(self.data_store[user_id])
                del self.data_store[user_id]
                self._log_action(user_id, "data_erased", "ALL", f"{count} items deleted")
            if user_id in self.consents:
                del self.consents[user_id]
            self._save_state()
            logger.info(f"Right to erasure executed for user {user_id}, {count} items deleted")
        except Exception as e:
            logger.error(f"Failed to execute right to erasure: {e}")
            raise
    
    def export_user_data(self, user_id: str) -> Dict:
        """Export all user data (Data portability)"""
        return {
            "user_id": user_id,
            "data": [{
                'content': item.content,
                'category': item.category.name,
                'user_id': item.user_id,
                'created_at': item.created_at.isoformat(),
                'retention_days': item.retention_days
            } for item in self.data_store.get(user_id, [])],
            "consents": [asdict(c) for c in self.consents.get(user_id, [])],
            "exported_at": datetime.now().isoformat()
        }
    
    def detect_breach_attempt(self, user_id: str) -> bool:
        """Detect potential data breach based on failed access patterns"""
        recent_logs = [log for log in self.audit_logs 
                      if log.user_id == user_id and 
                      log.result == "blocked" and
                      datetime.now() - log.timestamp < timedelta(minutes=10)]
        return len(recent_logs) >= self.breach_threshold
    
    def _log_action(self, user_id: str, action: str, category: str, result: str):
        """Internal audit logging"""
        self.audit_logs.append(
            AuditLog(datetime.now(), user_id, action, category, result)
        )
        # Trim if exceeds limit
        if len(self.audit_logs) > self.max_audit_logs * 1.5:
            self.audit_logs = self.audit_logs[-self.max_audit_logs:]
    
    def get_audit_report(self, user_id: Optional[str] = None) -> List[Dict]:
        """Generate audit report"""
        logs = [log for log in self.audit_logs if not user_id or log.user_id == user_id]
        return [asdict(log) for log in logs[-100:]]  # Last 100 entries
    
    def process_data(self, user_id: str, text: str, purpose: str) -> Dict:
        """Main processing with DPDP compliance checks"""
        try:
            category = self.classify_data(text)
            has_consent = self.check_consent(user_id, purpose)
            risk = self.assess_risk(category, has_consent)
            
            if self.detect_breach_attempt(user_id):
                self._log_action(user_id, "breach_detected", category.value, "blocked")
                logger.warning(f"Breach attempt detected for user {user_id}")
                return {
                    "status": "blocked",
                    "reason": "Potential breach detected",
                    "risk_level": RiskLevel.CRITICAL.value
                }
            
            if category in [DataCategory.PII, DataCategory.SENSITIVE, 
                           DataCategory.FINANCIAL, DataCategory.HEALTH] and not has_consent:
                self._log_action(user_id, "data_access", category.value, "blocked")
                logger.warning(f"Data access blocked for user {user_id}, no consent")
                return {
                    "status": "blocked",
                    "reason": "No consent for processing",
                    "category": category.value,
                    "risk_level": risk.value
                }
            
            self._log_action(user_id, "data_processed", category.value, "allowed")
            logger.info(f"Data processed for user {user_id}, category: {category.value}")
            return {
                "status": "allowed",
                "category": category.value,
                "risk_level": risk.value,
                "anonymized": self.anonymize(text)
            }
        except Exception as e:
            logger.error(f"Failed to process data: {e}")
            raise

if __name__ == "__main__":
    agent = DPDPAgent()
    
    # Example usage
    agent.grant_consent("user123", "marketing", duration_days=90)
    agent.store_data("user123", "Contact: john@example.com, Phone: 9876543210")
    
    result = agent.process_data(
        "user123", 
        "Contact: john@example.com, Phone: 9876543210",
        "marketing"
    )
    print("Processing Result:", result)
    
    # Export user data
    export = agent.export_user_data("user123")
    print("\nData Export:", json.dumps(export, indent=2, default=str))
    
    # Audit report
    print("\nAudit Logs:", len(agent.get_audit_report()))
    
    # Right to erasure
    agent.right_to_erasure("user123")
    print("\nData after erasure:", agent.data_store.get("user123", "Deleted"))
