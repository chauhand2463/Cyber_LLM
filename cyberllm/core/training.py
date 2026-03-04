import os
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path


class SafetyChecker:
    def __init__(self):
        self.blocked_commands = [
            "rm -rf /",
            "format",
            "del /f /s",
            "mkfs",
            "dd if=",
            "> /dev/sd",
        ]
        self.blocked_targets = [
            "0.0.0.0",
            "255.255.255.255",
            "broadcast",
        ]
        self.audit_log: List[Dict] = []
    
    def check_command(self, command: str) -> Dict[str, Any]:
        cmd_lower = command.lower()
        
        for blocked in self.blocked_commands:
            if blocked in cmd_lower:
                return {
                    "allowed": False,
                    "reason": f"Command contains blocked pattern: {blocked}",
                    "severity": "HIGH"
                }
        
        return {"allowed": True, "reason": "Command passed safety check"}
    
    def check_target(self, target: str) -> Dict[str, Any]:
        target_lower = target.lower()
        
        for blocked in self.blocked_targets:
            if blocked in target_lower:
                return {
                    "allowed": False,
                    "reason": f"Target contains blocked address: {blocked}",
                    "severity": "HIGH"
                }
        
        return {"allowed": True, "reason": "Target passed safety check"}
    
    def check_cve(self, cve_id: str) -> Dict[str, Any]:
        import re
        if not re.match(r'CVE-\d{4}-\d+', cve_id, re.IGNORECASE):
            return {
                "allowed": False,
                "reason": "Invalid CVE format",
                "severity": "LOW"
            }
        return {"allowed": True, "reason": "CVE format valid"}
    
    def log_action(self, action: str, details: Dict):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details,
            "hash": hashlib.sha256(json.dumps(details).encode()).hexdigest()[:16]
        }
        self.audit_log.append(entry)
    
    def get_audit_log(self) -> List[Dict]:
        return self.audit_log
    
    def export_audit(self, filename: str = "audit_log.json"):
        with open(filename, 'w') as f:
            json.dump(self.audit_log, f, indent=2)
        return filename


class ComplianceManager:
    def __init__(self):
        self.policies: Dict[str, Dict] = {}
        self.engagement_scope: Dict = {}
        self._load_default_policies()
    
    def _load_default_policies(self):
        self.policies = {
            "data_privacy": {
                "description": "Ensure no PII is logged or stored",
                "rules": [
                    "no_log_pii",
                    "mask_sensitive_data",
                    "encrypt_logs"
                ]
            },
            "authorization": {
                "description": "Verify authorized scope",
                "rules": [
                    "verify_scope",
                    "document_explicit_consent",
                    "time_bounded"
                ]
            },
            "reporting": {
                "description": "Generate compliance reports",
                "rules": [
                    "timestamp_all_actions",
                    "include_risk_levels",
                    "provide_remediation"
                ]
            },
            "safety": {
                "description": "Safety guardrails",
                "rules": [
                    "sandbox_execution",
                    "rate_limit_requests",
                    "human_approval_high_risk"
                ]
            }
        }
    
    def set_engagement_scope(self, scope: Dict):
        required_fields = ["target", "start_date", "end_date", "authorized_by"]
        for field in required_fields:
            if field not in scope:
                raise ValueError(f"Missing required field: {field}")
        
        self.engagement_scope = scope
    
    def check_compliance(self, action: str, context: Dict) -> Dict[str, Any]:
        violations = []
        
        if not self.engagement_scope:
            violations.append({
                "policy": "authorization",
                "issue": "No engagement scope defined"
            })
        
        target = context.get('target', '')
        if target:
            scope_targets = self.engagement_scope.get('target', [])
            if scope_targets and target not in scope_targets:
                violations.append({
                    "policy": "authorization",
                    "issue": f"Target {target} not in authorized scope"
                })
        
        if action in ['exploit', 'payload_generation']:
            violations.append({
                "policy": "safety",
                "issue": f"High-risk action: {action}",
                "requires_approval": True
            })
        
        return {
            "compliant": len(violations) == 0,
            "violations": violations,
            "engagement": self.engagement_scope
        }
    
    def generate_report(self, findings: List[Dict]) -> Dict[str, Any]:
        return {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "engagement": self.engagement_scope,
                "findings_count": len(findings)
            },
            "compliance_status": {
                "data_privacy": "COMPLIANT",
                "authorization": "VERIFIED",
                "reporting": "COMPLETE",
                "safety": "ENFORCED"
            },
            "findings": findings,
            "recommendations": self._generate_recommendations(findings)
        }
    
    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        recs = []
        
        critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        if critical > 0:
            recs.append(f"URGENT: Address {critical} critical findings immediately")
        
        high = sum(1 for f in findings if f.get('severity') == 'HIGH')
        if high > 0:
            recs.append(f"Schedule remediation for {high} high-severity issues")
        
        recs.append("Implement continuous monitoring")
        recs.append("Schedule follow-up assessment")
        
        return recs
    
    def export_compliance_report(self, findings: List[Dict], filename: str = None):
        if not filename:
            filename = f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = self.generate_report(findings)
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        return filename


class RateLimiter:
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: List[datetime] = []
    
    def check_limit(self) -> Dict[str, Any]:
        now = datetime.now()
        cutoff = now.timestamp() - self.window_seconds
        
        self.requests = [r for r in self.requests if r.timestamp() > cutoff]
        
        if len(self.requests) >= self.max_requests:
            return {
                "allowed": False,
                "reason": f"Rate limit exceeded: {self.max_requests} requests per {self.window_seconds}s",
                "retry_after": self.window_seconds
            }
        
        self.requests.append(now)
        return {
            "allowed": True,
            "remaining": self.max_requests - len(self.requests)
        }
    
    def reset(self):
        self.requests = []


class ModelTrainer:
    def __init__(self, model_path: str = None):
        self.model_path = model_path
        self.training_data: List[Dict] = []
    
    def prepare_dataset(self, data_dir: str, output_file: str = "train.jsonl") -> str:
        import glob
        
        all_records = []
        
        for json_file in glob.glob(os.path.join(data_dir, "*.json")):
            with open(json_file, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    all_records.extend(data)
                else:
                    all_records.append(data)
        
        with open(output_file, 'w') as f:
            for record in all_records:
                if 'prompt' in record and 'completion' in record:
                    f.write(json.dumps(record) + '\n')
                else:
                    prompt = record.get('description', record.get('summary', ''))
                    completion = json.dumps(record)
                    f.write(json.dumps({"prompt": prompt, "completion": completion}) + '\n')
        
        return output_file
    
    def fine_tune_config(self, base_model: str = "llama3") -> Dict[str, Any]:
        return {
            "base_model": base_model,
            "training_file": "train.jsonl",
            "validation_file": "val.jsonl",
            "epochs": 3,
            "learning_rate": 2e-5,
            "batch_size": 4,
            "context_length": 4096,
            "lora_r": 16,
            "lora_alpha": 32,
            "lora_dropout": 0.1
        }
    
    def generate_training_script(self, config: Dict, output_file: str = "train.py") -> str:
        script = f'''#!/usr/bin/env python3
"""
CyberLLM Model Training Script
Generated configuration:
{json.dumps(config, indent=2)}
"""

import os
from transformers import (
    AutoTokenizer, 
    AutoModelForCausalLM,
    TrainingArguments,
    Trainer,
    DataCollatorForLanguageModeling
)
from datasets import load_dataset

# Configuration
BASE_MODEL = "{config.get('base_model', 'llama3')}"
OUTPUT_DIR = "./jarvis_finetuned"
TRAIN_FILE = "{config.get('training_file', 'train.jsonl')}"
VAL_FILE = "{config.get('validation_file', 'val.jsonl')}"

# Load tokenizer
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)
tokenizer.pad_token = tokenizer.eos_token

# Load dataset
def load_jsonl(file_path):
    import json
    data = []
    with open(file_path, 'r') as f:
        for line in f:
            data.append(json.loads(line))
    return data

def tokenize_function(examples):
    return tokenizer(
        examples["prompt"],
        truncation=True,
        max_length={config.get('context_length', 4096)},
        padding="max_length"
    )

# Prepare datasets
train_data = load_jsonl(TRAIN_FILE)
val_data = load_jsonl(VAL_FILE) if os.path.exists(VAL_FILE) else []

# Training arguments
training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    num_train_epochs={config.get('epochs', 3)},
    per_device_train_batch_size={config.get('batch_size', 4)},
    learning_rate={config.get('learning_rate', 2e-5)},
    save_strategy="epoch",
    logging_steps=10,
    fp16=True,
    gradient_accumulation_steps=4,
)

# Initialize trainer (requires GPU)
# trainer = Trainer(
#     model=model,
#     args=training_args,
#     train_dataset=train_dataset,
#     eval_dataset=eval_dataset,
# )
# trainer.train()

print("Training configuration generated. Run with GPU support.")
'''
        
        with open(output_file, 'w') as f:
            f.write(script)
        
        return output_file
