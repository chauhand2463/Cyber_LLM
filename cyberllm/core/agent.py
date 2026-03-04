import os
import json
import subprocess
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Tool:
    name: str
    description: str
    function: Callable
    parameters: Dict[str, str]


class ToolRegistry:
    def __init__(self):
        self.tools: Dict[str, Tool] = {}
    
    def register(self, name: str, description: str, function: Callable, parameters: Dict[str, str] = None):
        self.tools[name] = Tool(name, description, function, parameters or {})
    
    def get_tool(self, name: str) -> Optional[Tool]:
        return self.tools.get(name)
    
    def list_tools(self) -> List[Dict]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters
            }
            for t in self.tools.values()
        ]
    
    def execute(self, name: str, **kwargs) -> Any:
        tool = self.get_tool(name)
        if not tool:
            return {"error": f"Tool '{name}' not found"}
        try:
            return tool.function(**kwargs)
        except Exception as e:
            return {"error": str(e)}


class AgentOrchestrator:
    def __init__(self, llm_client=None):
        self.llm = llm_client
        self.registry = ToolRegistry()
        self.execution_history: List[Dict] = []
        self._register_default_tools()
    
    def _register_default_tools(self):
        from cyberllm.core.scanner import Scanner
        from cyberllm.core.cti import CTIFeeds
        
        scanner = Scanner()
        cti = CTIFeeds()
        
        self.registry.register(
            "system_info",
            "Get system information (hostname, OS, user)",
            lambda: scanner.run_safe("systeminfo"),
            {"target": "optional - specific system"}
        )
        
        self.registry.register(
            "network_scan",
            "Scan network connections and ports",
            lambda: scanner.run_safe("network"),
            {"target": "optional - IP or network"}
        )
        
        self.registry.register(
            "process_list",
            "List running processes",
            lambda: scanner.get_processes()[:20],
            {"limit": "optional - number of processes"}
        )
        
        self.registry.register(
            "user_audit",
            "Audit user accounts and privileges",
            lambda: {
                "users": scanner.run_safe("users"),
                "admins": scanner.run_safe("admins")
            },
            {}
        )
        
        self.registry.register(
            "cve_lookup",
            "Look up CVE vulnerability details",
            lambda cve_id: cti.get_cve(cve_id),
            {"cve_id": "required - CVE identifier"}
        )
        
        self.registry.register(
            "cve_enrich",
            "Enrich CVE with threat intelligence",
            lambda cve_id: cti.enrich_cve(cve_id),
            {"cve_id": "required - CVE identifier"}
        )
        
        self.registry.register(
            "threat_intel",
            "Check IP threat intelligence",
            lambda ip: cti.threat_intel_ip(ip),
            {"ip": "required - IP address"}
        )
        
        self.registry.register(
            "recent_cves",
            "Get recent CVEs from NVD",
            lambda days=7: cti.get_recent_cves(days=days),
            {"days": "optional - number of days"}
        )
        
        self.registry.register(
            "service_scan",
            "Scan system services",
            lambda: scanner.run_safe("services"),
            {}
        )
        
        self.registry.register(
            "firewall_status",
            "Check firewall configuration",
            lambda: scanner.run_safe("firewall"),
            {}
        )
        
        self.registry.register(
            "startup_check",
            "Check startup programs",
            lambda: scanner.run_safe("startup"),
            {}
        )
    
    def plan_task(self, objective: str) -> Dict[str, Any]:
        if not self.llm:
            return self._default_plan(objective)
        
        tool_list = self.registry.list_tools()
        tools_desc = json.dumps(tool_list, indent=2)
        
        prompt = f"""You are an expert penetration tester. Given this objective, break it down into steps using available tools.

Available tools:
{tools_desc}

Objective: {objective}

Provide a JSON plan with:
- steps: array of {{"tool": "tool_name", "reason": "why", "params": {{}}}}
- estimated_time: minutes
- risk_level: LOW/MEDIUM/HIGH

Respond ONLY with valid JSON."""

        try:
            response = self.llm.chat(prompt)
            plan = json.loads(response)
            return {"status": "success", "plan": plan}
        except:
            return self._default_plan(objective)
    
    def _default_plan(self, objective: str) -> Dict[str, Any]:
        obj_lower = objective.lower()
        
        if "cve" in obj_lower:
            import re
            cve_match = re.search(r'CVE-\d{4}-\d+', objective, re.IGNORECASE)
            if cve_match:
                return {
                    "status": "success",
                    "plan": {
                        "steps": [
                            {"tool": "cve_enrich", "reason": "Get CVE details", "params": {"cve_id": cve_match.group()}}
                        ],
                        "estimated_time": 1,
                        "risk_level": "LOW"
                    }
                }
        
        if "network" in obj_lower or "port" in obj_lower:
            return {
                "status": "success",
                "plan": {
                    "steps": [
                        {"tool": "network_scan", "reason": "Scan network connections", "params": {}}
                    ],
                    "estimated_time": 2,
                    "risk_level": "LOW"
                }
            }
        
        if "user" in obj_lower or "admin" in obj_lower:
            return {
                "status": "success",
                "plan": {
                    "steps": [
                        {"tool": "user_audit", "reason": "Audit user accounts", "params": {}}
                    ],
                    "estimated_time": 1,
                    "risk_level": "LOW"
                }
            }
        
        return {
            "status": "success",
            "plan": {
                "steps": [
                    {"tool": "system_info", "reason": "Gather system info", "params": {}}
                ],
                "estimated_time": 1,
                "risk_level": "LOW"
            }
        }
    
    def execute_plan(self, plan: Dict, auto_approve: bool = True) -> Dict[str, Any]:
        results = []
        steps = plan.get('steps', [])
        
        for i, step in enumerate(steps):
            tool_name = step.get('tool')
            params = step.get('params', {})
            
            print(f"[{i+1}/{len(steps)}] Running {tool_name}...")
            
            result = self.registry.execute(tool_name, **params)
            
            step_result = {
                "step": i + 1,
                "tool": tool_name,
                "params": params,
                "result": result,
                "timestamp": datetime.now().isoformat()
            }
            
            results.append(step_result)
            self.execution_history.append(step_result)
        
        return {
            "status": "completed",
            "steps_executed": len(results),
            "results": results
        }
    
    def execute_objective(self, objective: str, auto_approve: bool = True) -> Dict[str, Any]:
        print(f"[+] Planning: {objective}")
        plan_result = self.plan_task(objective)
        
        if plan_result.get('status') != 'success':
            return plan_result
        
        plan = plan_result.get('plan', {})
        print(f"[+] Plan: {len(plan.get('steps', []))} steps")
        print(f"[+] Risk: {plan.get('risk_level', 'UNKNOWN')}")
        
        if not auto_approve:
            confirm = input("Execute plan? (y/n): ")
            if confirm.lower() != 'y':
                return {"status": "cancelled"}
        
        return self.execute_plan(plan, auto_approve=True)
    
    def get_history(self) -> List[Dict]:
        return self.execution_history
    
    def clear_history(self):
        self.execution_history = []


class ReasoningAgent:
    def __init__(self, orchestrator: AgentOrchestrator):
        self.orchestrator = orchestrator
        self.context: List[Dict] = []
    
    def think(self, observation: str) -> str:
        self.context.append({"role": "observation", "content": observation})
        
        if not self.orchestrator.llm:
            return self._simple_reasoning(observation)
        
        context_str = json.dumps(self.context[-5:])
        
        prompt = f"""Based on the observations, determine the next action.

Context:
{context_str}

Current observation: {observation}

Should we:
1. Gather more information (use a tool)
2. Analyze what we've found (explain to user)
3. Stop (task complete or blocked)

Respond with JSON: {{"action": "tool|explain|stop", "reason": "...", "tool": "tool_name if tool", "params": {{}}}}"""

        try:
            response = self.orchestrator.llm.chat(prompt)
            decision = json.loads(response)
            
            if decision.get('action') == 'tool':
                result = self.orchestrator.registry.execute(
                    decision.get('tool'),
                    **decision.get('params', {})
                )
                return f"Executed {decision.get('tool')}: {json.dumps(result)[:200]}"
            elif decision.get('action') == 'stop':
                return "Task stopped"
            else:
                return decision.get('reason', 'Analyzing...')
        except:
            return self._simple_reasoning(observation)
    
    def _simple_reasoning(self, observation: str) -> str:
        obs_lower = observation.lower()
        
        if 'error' in obs_lower or 'failed' in obs_lower:
            return "Encountered an issue. Let me try an alternative approach."
        elif 'success' in obs_lower or 'found' in obs_lower:
            return "Good progress. Let me gather more details."
        else:
            return "Processing..."
    
    def reset(self):
        self.context = []


class SandboxExecutor:
    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self.execution_log: List[Dict] = []
    
    def execute_code(self, code: str, language: str = "python", timeout: int = 30) -> Dict[str, Any]:
        if not self.enabled:
            return {
                "status": "disabled",
                "message": "Sandbox execution is disabled. Enable in configuration."
            }
        
        log_entry = {
            "code": code,
            "language": language,
            "timestamp": datetime.now().isoformat(),
            "status": "pending"
        }
        
        try:
            if language == "python":
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                    f.write(code)
                    temp_file = f.name
                
                result = subprocess.run(
                    ["python", temp_file],
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                
                output = result.stdout if result.stdout else result.stderr
                log_entry.update({"status": "completed", "output": output})
                
                os.unlink(temp_file)
            
            elif language in ["bash", "shell"]:
                result = subprocess.run(
                    code,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                output = result.stdout if result.stdout else result.stderr
                log_entry.update({"status": "completed", "output": output})
            
            else:
                log_entry.update({"status": "error", "output": f"Unsupported language: {language}"})
        
        except subprocess.TimeoutExpired:
            log_entry.update({"status": "timeout", "output": "Execution timed out"})
        except Exception as e:
            log_entry.update({"status": "error", "output": str(e)})
        
        self.execution_log.append(log_entry)
        return log_entry
    
    def get_log(self) -> List[Dict]:
        return self.execution_log
