# How to Use the Multi-Agent Framework

You have two ways to give tasks to your program:

## 1. Ad-Hoc Mode (Quick Tasks)
Use this for one-off requests where you want the agents to figure out the plan dynamically.

**Syntax:**
```powershell
.\run_framework.ps1 "Your natural language instruction here"
```

**Examples:**
```powershell
.\run_framework.ps1 "Check the system uptime and list active users"
```
```powershell
.\run_framework.ps1 "Create a file called summary.txt containing the current date"
```

*Note: In this mode, the agents collaborate in a Group Chat to solve your request.*

## 2. Scenario Mode (Repeatable Workflows)
Use this for robust, step-by-step procedures that you have defined in code (resilient to errors).

**Syntax:**
```powershell
.\run_framework.ps1 --scenario <scenario_name>
```

**Available Scenarios:**
- `threat_hunt`: List files -> Analyze for threats -> Summarize.
- `sys_info`: Get Hostname/OS -> Summarize.
- `net_check`: Netstat -> Analyze ports.
- `file_content`: Create dummy file -> Read it -> Analyze content.
- `process_check`: Tasklist -> Analyze processes.

**Example:**
```powershell
.\run_framework.ps1 --scenario process_check
```

## 3. The Full Program (Advanced Threat Hunt)
This is the flagship scenario associated with the "Full Program". It runs the entire intelligence pipeline:
Normalization -> IOC Extraction -> Threat Classification -> Risk Scoring -> Decision Engine -> Correlation -> Final Report.

**Syntax:**
```powershell
.\run_framework.ps1 --scenario adv_threat_hunt
```

## How to Add New Scenarios

1.  Open `scenarios/definitions.py`.
2.  Define a new class inheriting from `Scenario`.
3.  Add `ScenarioStep` items to the `steps` list.
4.  Register it in `SCENARIOS` dictionary in `run_framework.py`.

```python
class MyNewScenario(Scenario):
    name = "My Custom Task"
    steps = [
         ScenarioStep("step1", "cmd_exec_agent", "echo hello"),
         ScenarioStep("step2", "text_analyst_agent", "Analyze {step1_output}")
    ]
```
