"""DPDP Privacy AI Agent - Production Implementation"""

import re
import json
import logging
import threading
import os
import base64
from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Module-specific handlers (don't pollute root logger for library consumers)
_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# Log file path is configurable via DPDP_LOG_FILE so deployments can direct logs
# into a dedicated directory (e.g. logs/dpdp_agent.log). Defaults to CWD.
_log_file = os.environ.get('DPDP_LOG_FILE', 'dpdp_agent.log')
_log_dir = os.path.dirname(_log_file)
if _log_dir:
    os.makedirs(_log_dir, exist_ok=True)
_file_handler = logging.FileHandler(_log_file)
_file_handler.setFormatter(_formatter)
logger.addHandler(_file_handler)
_stream_handler = logging.StreamHandler()
_stream_handler.setFormatter(_formatter)
logger.addHandler(_stream_handler)


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
    content: str  # Stored encrypted in memory
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
    # Shared PII patterns used by both classify_data and anonymize.
    # Order matters for anonymization: longer/more-specific patterns first to prevent
    # partial matches (e.g., card before phone/aadhaar).
    PII_PATTERNS = {
        'email': (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), '[EMAIL]'),
        'card': (re.compile(r'(?<!\d)\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)'), '[CARD]'),
        'aadhaar': (re.compile(r'(?<!\d)[2-9]\d{3}\s?\d{4}\s?\d{4}(?!\d)'), '[AADHAAR]'),
        'phone': (re.compile(r'(?<!\d)[6-9]\d{9}(?!\d)'), '[PHONE]'),
    }
    HEALTH_PATTERNS = [re.compile(r'\b(diabetes|hypertension|cancer|HIV)\b', re.IGNORECASE)]

    def __init__(self, storage_path: Optional[str] = None, encryption_key: Optional[str] = None,
                 config_path: str = "config.json"):
        # Load config
        self._config = self._load_config(config_path)

        # Apply config defaults
        if storage_path is None:
            storage_path = self._config.get("storage_path", "data/dpdp_storage.json")

        self.breach_threshold = self._config.get("breach_threshold", 5)
        self.default_retention_days = self._config.get("default_retention_days", 365)
        self.max_audit_logs = 1000

        # Set log level from config
        log_level = self._config.get("log_level", "INFO")
        logger.setLevel(getattr(logging, log_level, logging.INFO))

        # Build compiled pattern lookup for classify_data
        # Check FINANCIAL first (16 digits) before PII (10/12 digits) to avoid partial matches
        self.compiled_patterns = {
            DataCategory.FINANCIAL: [self.PII_PATTERNS['card'][0]],
            DataCategory.PII: [self.PII_PATTERNS['email'][0],
                               self.PII_PATTERNS['phone'][0],
                               self.PII_PATTERNS['aadhaar'][0]],
            DataCategory.HEALTH: self.HEALTH_PATTERNS,
        }

        # State
        self.consents: Dict[str, List[ConsentRecord]] = {}
        self.data_store: Dict[str, List[DataItem]] = {}  # Content stored ENCRYPTED
        self.audit_logs: List[AuditLog] = []

        # Thread safety - RLock allows same thread to re-acquire
        self._lock = threading.RLock()

        # Storage path
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

        # Setup encryption - require a valid key
        self.cipher = self._setup_encryption(encryption_key)

        self._load_state()
        logger.info("DPDPAgent initialized")

    @staticmethod
    def _load_config(config_path: str) -> dict:
        """Load configuration from JSON file"""
        try:
            path = Path(config_path)
            if path.exists():
                with open(path, 'r') as f:
                    config = json.load(f)
                logger.info(f"Config loaded from {config_path}")
                return config
        except Exception as e:
            logger.warning(f"Failed to load config from {config_path}: {e}")
        return {}

    def _setup_encryption(self, encryption_key: Optional[str]) -> Fernet:
        """Setup Fernet encryption with proper key validation"""
        key = encryption_key or os.environ.get('DPDP_ENCRYPTION_KEY')

        if not key:
            raise ValueError(
                "Encryption key required. Set DPDP_ENCRYPTION_KEY environment variable "
                "or pass encryption_key parameter. Generate one with: "
                "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )

        # If it's a valid 44-char base64 Fernet key, use directly
        if len(key) == 44:
            try:
                return Fernet(key.encode())
            except Exception:
                pass  # Fall through to KDF

        # Otherwise, derive a key using PBKDF2 with a per-deployment random salt.
        logger.info("Deriving encryption key from passphrase using PBKDF2")
        salt = self._get_or_create_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
        return Fernet(derived_key)

    # Legacy static salt used before per-deployment salts were introduced.
    # Retained only to derive the salt file location and for reference; new
    # deployments generate a random salt stored alongside the data.
    _LEGACY_SALT = b'dpdp-privacy-agent-v1-salt-value'

    def _get_or_create_salt(self) -> bytes:
        """Return a per-deployment random salt, creating and persisting one if absent.

        The salt is stored next to the data file (e.g. data/dpdp_storage.salt).
        If no salt file exists but a storage file already does, we fall back to the
        legacy static salt so existing passphrase-encrypted data remains readable.
        """
        salt_path = self.storage_path.with_suffix('.salt')
        try:
            if salt_path.exists():
                salt = salt_path.read_bytes()
                if salt:
                    return salt
            # No salt file. If a data file already exists, this deployment predates
            # per-deployment salts -> keep legacy salt for backward compatibility.
            if self.storage_path.exists():
                logger.warning("No salt file found but data exists; using legacy salt "
                               "for backward compatibility. Consider re-encrypting.")
                return self._LEGACY_SALT
            # Fresh deployment: generate and persist a random salt.
            salt = os.urandom(16)
            salt_path.parent.mkdir(parents=True, exist_ok=True)
            # Write atomically and restrict permissions where supported.
            tmp = salt_path.with_suffix('.salt.tmp')
            tmp.write_bytes(salt)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            tmp.replace(salt_path)
            logger.info("Generated new per-deployment encryption salt")
            return salt
        except OSError as e:
            # If we cannot read/write the salt file, fail loud rather than silently
            # deriving an unrecoverable key.
            raise RuntimeError(f"Failed to read or create encryption salt at {salt_path}: {e}")

    def _encrypt(self, data: str) -> str:
        """Encrypt sensitive data"""
        return self.cipher.encrypt(data.encode()).decode()

    def _decrypt(self, data: str) -> str:
        """Decrypt sensitive data"""
        return self.cipher.decrypt(data.encode()).decode()

    def _serialize_record(self, obj) -> dict:
        """Serialize a dataclass record with proper enum/datetime handling"""
        result = {}
        for key, value in obj.__dict__.items():
            if isinstance(value, Enum):
                result[key] = value.value
            elif isinstance(value, datetime):
                result[key] = value.isoformat()
            elif value is None:
                result[key] = None
            else:
                result[key] = value
        return result

    def _load_state(self):
        """Load persisted state from disk.

        A missing storage file is normal (fresh deployment) and handled silently.
        A corrupt/unreadable file is backed up and logged loudly rather than being
        silently discarded, so operators can investigate and recover.
        """
        with self._lock:
            if not self.storage_path.exists():
                logger.info("No existing state file; starting fresh")
                return
            try:
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                self._backup_corrupt_state()
                logger.error("State file at %s is corrupt or unreadable (%s); "
                             "backed up and starting with empty state",
                             self.storage_path, e)
                return

            try:
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

                # Load data store - content stays ENCRYPTED in memory
                for user_id, items in data.get('data_store', {}).items():
                    self.data_store[user_id] = [
                        DataItem(
                            i['content'],  # Keep encrypted
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
            except (KeyError, ValueError, TypeError) as e:
                # Structurally valid JSON but unexpected schema -> treat as corruption.
                self._backup_corrupt_state()
                # Reset any partially-populated state to avoid inconsistency.
                self.consents.clear()
                self.data_store.clear()
                self.audit_logs.clear()
                logger.error("State file at %s has unexpected structure (%s); "
                             "backed up and starting with empty state",
                             self.storage_path, e)

    def _backup_corrupt_state(self):
        """Move a corrupt state file aside so it is not overwritten on next save."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            backup = self.storage_path.with_suffix(f'.corrupt-{timestamp}.bak')
            self.storage_path.replace(backup)
            logger.error("Corrupt state file backed up to %s", backup)
        except OSError as e:
            logger.error("Failed to back up corrupt state file: %s", e)

    def _parse_category(self, category_str: str) -> DataCategory:
        """Parse category from string, handling both enum name and value"""
        try:
            return DataCategory[category_str]
        except KeyError:
            for cat in DataCategory:
                if cat.value == category_str:
                    return cat
            return DataCategory.GENERAL

    def _save_state(self):
        """Persist state to disk with atomic write. Safe to call with or without _lock held (uses RLock)."""
        with self._lock:
            try:
                data = {
                    'consents': {
                        uid: [self._serialize_record(c) for c in consents]
                        for uid, consents in self.consents.items()
                    },
                    'data_store': {
                        uid: [{
                            'content': item.content,  # Already encrypted in memory
                            'category': item.category.name,
                            'user_id': item.user_id,
                            'created_at': item.created_at.isoformat(),
                            'retention_days': item.retention_days
                        } for item in items]
                        for uid, items in self.data_store.items()
                    },
                    'audit_logs': [self._serialize_record(log) for log in self.audit_logs[-self.max_audit_logs:]],
                    'last_saved': datetime.now().isoformat()
                }

                # Atomic write: write to temp file, then rename
                temp_path = self.storage_path.with_suffix('.tmp')
                with open(temp_path, 'w') as f:
                    json.dump(data, f, indent=2)
                temp_path.replace(self.storage_path)

                # Trim in-memory audit logs
                if len(self.audit_logs) > self.max_audit_logs:
                    self.audit_logs = self.audit_logs[-self.max_audit_logs:]

                logger.info("State saved to disk")
            except Exception as e:
                logger.error(f"Failed to save state: {e}")

    def _log_action(self, user_id: str, action: str, category: str, result: str):
        """Internal audit logging. Caller must hold _lock or call within locked context."""
        self.audit_logs.append(
            AuditLog(datetime.now(), user_id, action, category, result)
        )
        # Trim if exceeds limit (single, consistent policy with _save_state)
        if len(self.audit_logs) > self.max_audit_logs:
            self.audit_logs = self.audit_logs[-self.max_audit_logs:]

    @staticmethod
    def _sanitize_for_log(value: str) -> str:
        """Remove control characters from user input to prevent log injection."""
        return value.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')

    @staticmethod
    def _validate_str(value, name: str) -> str:
        """Validate that a value is a non-empty string, return it stripped."""
        if not isinstance(value, str):
            raise ValueError(f"{name} must be a string")
        value = value.strip()
        if not value:
            raise ValueError(f"{name} is required")
        return value

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
        if not isinstance(user_id, str) or not isinstance(purpose, str):
            return False
        with self._lock:
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
            user_id = self._validate_str(user_id, "user_id")
            purpose = self._validate_str(purpose, "purpose")

            if len(user_id) > 255 or len(purpose) > 255:
                raise ValueError("user_id and purpose must be <= 255 characters")

            if duration_days is not None:
                if isinstance(duration_days, bool) or not isinstance(duration_days, int) or duration_days <= 0:
                    raise ValueError("duration_days must be a positive integer")

            with self._lock:
                if user_id not in self.consents:
                    self.consents[user_id] = []

                # Check for duplicate
                for c in self.consents[user_id]:
                    if c.purpose == purpose and c.status == ConsentStatus.GRANTED:
                        logger.warning("Consent already exists for user %s, purpose: %s",
                                       self._sanitize_for_log(user_id),
                                       self._sanitize_for_log(purpose))
                        return

                expires = datetime.now() + timedelta(days=duration_days) if duration_days else None
                self.consents[user_id].append(
                    ConsentRecord(user_id, purpose, ConsentStatus.GRANTED, datetime.now(), expires)
                )
                self._log_action(user_id, "consent_granted", "N/A", f"Purpose: {purpose}")
                self._save_state()

            logger.info("Consent granted for user %s, purpose: %s",
                        self._sanitize_for_log(user_id), self._sanitize_for_log(purpose))
        except Exception as e:
            logger.error("Failed to grant consent: %s", e)
            raise

    def revoke_consent(self, user_id: str, purpose: str):
        """Revoke user consent"""
        try:
            user_id = self._validate_str(user_id, "user_id")
            purpose = self._validate_str(purpose, "purpose")

            with self._lock:
                if user_id not in self.consents:
                    logger.warning("No consents found for user %s",
                                   self._sanitize_for_log(user_id))
                    return

                found = False
                for consent in self.consents[user_id]:
                    if consent.purpose == purpose and consent.status == ConsentStatus.GRANTED:
                        consent.status = ConsentStatus.REVOKED
                        self._log_action(user_id, "consent_revoked", "N/A", f"Purpose: {purpose}")
                        found = True

                if not found:
                    logger.warning("No active consent found for user %s, purpose: %s",
                                   self._sanitize_for_log(user_id),
                                   self._sanitize_for_log(purpose))
                    return

                self._save_state()

            logger.info("Consent revoked for user %s, purpose: %s",
                        self._sanitize_for_log(user_id), self._sanitize_for_log(purpose))
        except Exception as e:
            logger.error("Failed to revoke consent: %s", e)
            raise

    def anonymize(self, text: str) -> str:
        """Anonymize PII in text using shared patterns"""
        for _name, (pattern, replacement) in self.PII_PATTERNS.items():
            text = pattern.sub(replacement, text)
        return text

    def store_data(self, user_id: str, text: str, retention_days: Optional[int] = None,
                   purpose: Optional[str] = None):
        """Store data with retention policy - encrypts before storing.
        
        For sensitive categories (PII, Financial, Health, Sensitive), consent must be
        verified. Pass the 'purpose' parameter to enable consent checking. If purpose
        is not provided for sensitive data, storage is blocked per DPDP requirements.
        """
        try:
            user_id = self._validate_str(user_id, "user_id")
            text = self._validate_str(text, "text")

            if len(user_id) > 255:
                raise ValueError("user_id must be <= 255 characters")
            if len(text) > 100000:
                raise ValueError("text must be <= 100000 characters")

            if retention_days is None:
                retention_days = self.default_retention_days
            elif isinstance(retention_days, bool) or not isinstance(retention_days, int) or retention_days <= 0:
                raise ValueError("retention_days must be a positive integer")

            if purpose is not None:
                purpose = self._validate_str(purpose, "purpose")

            category = self.classify_data(text)

            # DPDP compliance: require consent for storing sensitive data
            sensitive_categories = [DataCategory.PII, DataCategory.SENSITIVE,
                                    DataCategory.FINANCIAL, DataCategory.HEALTH]
            if category in sensitive_categories:
                if not purpose:
                    raise ValueError(
                        f"purpose is required when storing {category.value}. "
                        "Consent must be verified for sensitive data."
                    )
                if not self.check_consent(user_id, purpose):
                    with self._lock:
                        # result must be "blocked" so detect_breach_attempt counts it
                        self._log_action(user_id, "data_store_blocked", category.value,
                                         "blocked")
                        self._save_state()
                    raise PermissionError(
                        f"No consent for storing {category.value}. "
                        f"User must grant consent for purpose '{self._sanitize_for_log(purpose)}' first."
                    )

            encrypted_content = self._encrypt(text)

            with self._lock:
                if user_id not in self.data_store:
                    self.data_store[user_id] = []
                item = DataItem(encrypted_content, category, user_id, datetime.now(), retention_days)
                self.data_store[user_id].append(item)
                self._log_action(user_id, "data_stored", category.value, "success")
                self._save_state()

            logger.info("Data stored for user %s, category: %s",
                        self._sanitize_for_log(user_id), category.value)
        except (ValueError, PermissionError):
            raise
        except Exception as e:
            logger.error("Failed to store data: %s", e)
            raise

    def get_user_data(self, user_id: str) -> List[Dict]:
        """Get decrypted user data items. Skips items that fail to decrypt."""
        user_id = self._validate_str(user_id, "user_id")
        with self._lock:
            items = list(self.data_store.get(user_id, []))
        results = []
        for item in items:
            try:
                content = self._decrypt(item.content)
            except Exception:
                logger.warning("Failed to decrypt data item for user %s, skipping",
                               self._sanitize_for_log(user_id))
                content = "[DECRYPTION_FAILED]"
            results.append({
                'content': content,
                'category': item.category.name,
                'user_id': item.user_id,
                'created_at': item.created_at.isoformat(),
                'retention_days': item.retention_days
            })
        return results

    def delete_expired_data(self) -> int:
        """Delete data past retention period"""
        try:
            with self._lock:
                deleted = 0
                for user_id in list(self.data_store.keys()):
                    items = self.data_store[user_id]
                    expired = [i for i in items if
                               datetime.now() > i.created_at + timedelta(days=i.retention_days)]
                    deleted += len(expired)
                    remaining = [i for i in items if i not in expired]
                    if remaining:
                        self.data_store[user_id] = remaining
                    else:
                        # Remove empty user entries to prevent unbounded growth
                        del self.data_store[user_id]

                if deleted > 0:
                    self._save_state()

            logger.info(f"Deleted {deleted} expired data items")
            return deleted
        except Exception as e:
            logger.error(f"Failed to delete expired data: {e}")
            return 0

    def right_to_erasure(self, user_id: str):
        """Delete all user data (Right to be forgotten)"""
        try:
            user_id = self._validate_str(user_id, "user_id")

            with self._lock:
                count = 0
                if user_id in self.data_store:
                    count = len(self.data_store[user_id])
                    del self.data_store[user_id]
                    self._log_action(user_id, "data_erased", "ALL", f"{count} items deleted")
                if user_id in self.consents:
                    del self.consents[user_id]
                self._save_state()

            logger.info("Right to erasure executed for user %s, %d items deleted",
                        self._sanitize_for_log(user_id), count)
        except Exception as e:
            logger.error("Failed to execute right to erasure: %s", e)
            raise

    def export_user_data(self, user_id: str) -> Dict:
        """Export all user data (Data portability) - logged as high-risk event"""
        user_id = self._validate_str(user_id, "user_id")

        with self._lock:
            self._log_action(user_id, "data_exported", "ALL", "high_risk_export")
            items = list(self.data_store.get(user_id, []))
            consents = list(self.consents.get(user_id, []))
            self._save_state()

        exported_data = []
        for item in items:
            try:
                content = self._decrypt(item.content)
            except Exception:
                logger.warning("Failed to decrypt data item for user %s during export, skipping",
                               self._sanitize_for_log(user_id))
                content = "[DECRYPTION_FAILED]"
            exported_data.append({
                'content': content,
                'category': item.category.name,
                'user_id': item.user_id,
                'created_at': item.created_at.isoformat(),
                'retention_days': item.retention_days
            })

        return {
            "user_id": user_id,
            "data": exported_data,
            "consents": [self._serialize_record(c) for c in consents],
            "exported_at": datetime.now().isoformat()
        }

    def detect_breach_attempt(self, user_id: str) -> bool:
        """Detect potential data breach based on failed access patterns"""
        with self._lock:
            recent_logs = [log for log in self.audit_logs
                           if log.user_id == user_id and
                           log.result == "blocked" and
                           datetime.now() - log.timestamp < timedelta(minutes=10)]
        return len(recent_logs) >= self.breach_threshold

    def get_audit_report(self, user_id: Optional[str] = None) -> List[Dict]:
        """Generate audit report"""
        if user_id is not None and not isinstance(user_id, str):
            raise ValueError("user_id must be a string")
        with self._lock:
            logs = [log for log in self.audit_logs if not user_id or log.user_id == user_id]
            return [self._serialize_record(log) for log in logs[-100:]]

    def process_data(self, user_id: str, text: str, purpose: str) -> Dict:
        """Main processing with DPDP compliance checks"""
        try:
            user_id = self._validate_str(user_id, "user_id")
            text = self._validate_str(text, "text")
            purpose = self._validate_str(purpose, "purpose")

            if len(user_id) > 255 or len(purpose) > 255:
                raise ValueError("user_id and purpose must be <= 255 characters")
            if len(text) > 100000:
                raise ValueError("text must be <= 100000 characters")

            category = self.classify_data(text)
            has_consent = self.check_consent(user_id, purpose)
            risk = self.assess_risk(category, has_consent)

            if self.detect_breach_attempt(user_id):
                with self._lock:
                    self._log_action(user_id, "breach_detected", category.value, "blocked")
                    self._save_state()
                logger.warning("Breach attempt detected for user %s",
                               self._sanitize_for_log(user_id))
                return {
                    "status": "blocked",
                    "reason": "Potential breach detected",
                    "risk_level": RiskLevel.CRITICAL.value
                }

            if category in [DataCategory.PII, DataCategory.SENSITIVE,
                            DataCategory.FINANCIAL, DataCategory.HEALTH] and not has_consent:
                with self._lock:
                    self._log_action(user_id, "data_access", category.value, "blocked")
                    self._save_state()
                logger.warning("Data access blocked for user %s, no consent",
                               self._sanitize_for_log(user_id))
                return {
                    "status": "blocked",
                    "reason": "No consent for processing",
                    "category": category.value,
                    "risk_level": risk.value
                }

            with self._lock:
                self._log_action(user_id, "data_processed", category.value, "allowed")
                self._save_state()
            logger.info("Data processed for user %s, category: %s",
                        self._sanitize_for_log(user_id), category.value)
            return {
                "status": "allowed",
                "category": category.value,
                "risk_level": risk.value,
                "anonymized": self.anonymize(text)
            }
        except Exception as e:
            logger.error("Failed to process data: %s", e)
            raise


if __name__ == "__main__":
    # Generate a key for demo purposes
    demo_key = Fernet.generate_key().decode()
    print(f"Using generated key: {demo_key}")

    agent = DPDPAgent(encryption_key=demo_key)

    # Example usage
    agent.grant_consent("user123", "marketing", duration_days=90)
    agent.store_data("user123", "Contact: john@example.com, Phone: 9876543210", purpose="marketing")

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
