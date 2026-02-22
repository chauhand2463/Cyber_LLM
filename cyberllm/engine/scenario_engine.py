import autogen_compat as autogen
from autogen_compat import UserProxyAgent
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
import json
import logging
import re
from engine.memory_store import MemoryStore

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ScenarioStep:
    step_name: str
    save_output_to_context_key: Optional[str] = None
    agent_name: Optional[str] = None
    instruction_template: Optional[str] = None
    function_call: Optional[Callable] = None # For deterministic python steps
    condition: Optional[Callable] = None # Function(context) -> bool. If False, skip step.

class Scenario:
    name: str = "Base Scenario"
    steps: List[ScenarioStep] = []

    def get_steps(self) -> List[ScenarioStep]:
        return self.steps

class ScenarioRunner:
    def __init__(self, agent_map: Dict[str, autogen.ConversableAgent]):
        self.agent_map = agent_map
        self.context: Dict[str, Any] = {}
        self.memory_store = MemoryStore() # Initialize Memory
        
        # We need a user proxy to initiate chats
        self.user_proxy = autogen.UserProxyAgent(
            name="scenario_runner",
            human_input_mode="NEVER",
            code_execution_config={"work_dir": "llm_working_folder/code", "use_docker": False},
            is_termination_msg=lambda x: "TERMINATE" in x.get("content", "")
        )
        
        # Register tools to the user proxy so it can execute them when agents suggest them
        from tools.code_tools import exec_shell_command
        self.user_proxy.register_for_execution(name="exec_shell_command")(exec_shell_command)
        
        from tools.web_tools import download_web_page, detect_telemetry_gaps
        self.user_proxy.register_for_execution(name="download_web_page")(download_web_page)
        self.user_proxy.register_for_execution(name="detect_telemetry_gaps")(detect_telemetry_gaps)

    def run(self, scenario: Scenario):
        logger.info(f"Starting Scenario: {scenario.name}")
        
        for step in scenario.get_steps():
            logger.info(f"--- Executing Step: {step.step_name} ---")
            
            # Check Condition Guard
            if step.condition:
                try:
                    should_run = step.condition(self.context)
                    if not should_run:
                        logger.info(f"Skipping step '{step.step_name}': Condition met (Skipped).")
                        # Optional: Add a note to context that it was skipped?
                        continue
                except Exception as e:
                    logger.warning(f"Condition check failed for '{step.step_name}': {e}. Proceeding.")

            # 0. Handle Deterministic Function Steps
            if step.function_call:
                try:
                    # Pass context as kwargs? Or specific keys?
                    # Let's pass the whole context dictionary for flexibility
                    # We might need to inspect arguments, but for now assuming the function takes context or specific known keys.
                    # Or better, we interpolate arguments in the definition?
                    # Simpler: The function just takes a specific Indicator List.
                    # Let's assume usage: func(context['key'])
                    # Implementation specific: Let's assume the function_call is a lambda or partial, OR we pass the Context.
                    
                    # Better approach helper: execute the function with the self.context as arguments if possible
                    # or just pass the context dict if it accepts 'context'
                    
                    # For RiskScoringEngine.calculate_score(indicators=...), we need to pass the list.
                    # We can use a lambda in the definition: lambda context: RiskEngine.calc(context['indicators'])
                    
                    result = step.function_call(self.context)
                    
                    logger.info(f"Step Result (Function): {result}")
                    if step.save_output_to_context_key:
                        self.context[step.save_output_to_context_key] = result
                    
                    # Log to Memory
                    self.memory_store.log_step(
                        scenario_name=scenario.name,
                        step_name=step.step_name,
                        agent_name="InternalFunction",
                        input_text="Function execution",
                        output_text=result
                    )
                    
                    logger.info(f"--- Step '{step.step_name}' Complete ---\n")
                    continue
                except Exception as e:
                    logger.error(f"Function Execution Failed: {e}")
                    continue

            # 1. Prepare Instruction
            try:
                instruction = step.instruction_template.format(**self.context)
            except KeyError as e:
                logger.error(f"Missing context key for step '{step.step_name}': {e}")
                return

            # 2. Identify Agent
            agent = self.agent_map.get(step.agent_name)
            if not agent:
                logger.error(f"Agent '{step.agent_name}' not found.")
                return

            # Check if agent is a CmdExecutor (direct command execution without LLM)
            from agents.code_agents import CmdExecutor
            if isinstance(agent, CmdExecutor):
                try:
                    result = agent.run(instruction)
                    if result.get("status") == "error":
                        error_msg = result.get("error", "Unknown error")
                        logger.error(f"Command execution failed: {error_msg}")
                        raise RuntimeError(error_msg)
                    output_val = result.get("output", "")
                    if step.save_output_to_context_key:
                        self.context[step.save_output_to_context_key] = output_val
                    logger.info(f"Step Result: {output_val}")
                    self.memory_store.log_step(
                        scenario_name=scenario.name,
                        step_name=step.step_name,
                        agent_name=step.agent_name,
                        input_text=instruction,
                        output_text=output_val
                    )
                    logger.info(f"--- Step '{step.step_name}' Complete ---\n")
                    continue
                except Exception as e:
                    logger.error(f"Error executing command in step '{step.step_name}': {e}")
                    raise RuntimeError(f"Step '{step.step_name}' failed: {e}")

            # 3. Execute Step (Initiate Chat)
            # We use max_turns=2 to allow for standard tool execution loops (Agent -> Tool -> Agent)
            # If we let AutoGen handle it, we need a ConversableAgent as the user_proxy that can execute code/tools.
            
            # For this implementation, let's enable tool execution in the user_proxy for this runner.
            self.user_proxy._code_execution_config = {"use_docker": False, "work_dir": "llm_working_folder/code"}
            
            # We initiate chat. If the agent calls a tool, the user_proxy (if configured)            # 3. Execute Step (Initiate Chat)
            # We use max_turns=1 to avoid AutoGen attempting to execute the tool and crashing.
            # We will handle the tool execution manually if needed.
            
            try:
                chat_result = self.user_proxy.initiate_chat(
                    agent,
                    message=instruction,
                    max_turns=1,
                    summary_method="last_msg"
                )
            except Exception as e:
                logger.error(f"Error during agent interaction in step '{step.step_name}': {e}")
                
                # FALLBACK: Try to extract command from 'failed_generation' in error message
                # Groq/Llama 3 often returns <function=name {args}> which triggers 400 error
                err_str = str(e)
                cmd_match = re.search(r'(?:<function=exec_shell_command|exec_shell_command)\s*({.*?})(?:</function>)?', err_str)
                
                if cmd_match:
                    try:
                        args_str = cmd_match.group(1)
                        # Fix malformed JSON if necessary (e.g. missing quotes)
                        # But assuming generic JSON for now
                        args = json.loads(args_str)
                        cmd = args.get("shell_command")
                        
                        logger.info(f"Recovered command from error: {cmd}")
                        from tools.code_tools import exec_shell_command
                        result_dict = exec_shell_command(cmd)
                        
                        if result_dict.get("returncode") == 0:
                            chat_result = None # Still None but we have output
                            # Use a dummy object or just set output directly
                            if step.save_output_to_context_key:
                                self.context[step.save_output_to_context_key] = result_dict.get("stdout")
                            logger.info(f"Step Result (Recovered): {result_dict.get('stdout')}")
                            logger.info(f"--- Step '{step.step_name}' Complete ---\n")
                            continue # Move to next step
                        else:
                            logger.error(f"Command failed: {result_dict.get('stderr')}")
                    except Exception as parse_err:
                        logger.error(f"Failed to recover command from error: {parse_err}")

                chat_result = None

            # 4. Extract Output
            output_val = None
            if chat_result and chat_result.chat_history:
                last_msg = chat_result.chat_history[-1]
                
                # Check for tool calls (OpenAI format)
                tool_calls = last_msg.get("tool_calls")
                
                if tool_calls:
                    # Handle tool calls manually
                    for tool_call in tool_calls:
                        func_name = tool_call.get("function", {}).get("name")
                        func_args_str = tool_call.get("function", {}).get("arguments")
                        
                        if func_name == "exec_shell_command":
                            try:
                                args = json.loads(func_args_str)
                                cmd = args.get("shell_command")
                                logger.info(f"Manually executing command: {cmd}")
                                
                                from tools.code_tools import exec_shell_command
                                # exec_shell_command returns a DICT now
                                result_dict = exec_shell_command(cmd)
                                
                                # If returncode is 0, usage 'stdout', else 'stderr'
                                if result_dict.get("returncode") == 0:
                                    output_val = result_dict.get("stdout")
                                else:
                                    logger.error(f"Command failed: {result_dict.get('stderr')}")
                                    output_val = f"Error: {result_dict.get('stderr')}"
                                
                                # We only support one tool call result for now
                                break 
                            except Exception as e:
                                logger.error(f"Failed to execute manual tool call: {e}")
                                output_val = f"Execution Error: {str(e)}"
                else:
                    # Fallback
                    output_val = last_msg.get("content", "")
                    
                    # Try to parse if it's a JSON string
                    if output_val and isinstance(output_val, str) and output_val.strip().startswith("{"):
                        try:
                            parsed_json = json.loads(output_val)
                            
                            # Check for Custom Command Action (Groq Compatibility Mode)
                            if isinstance(parsed_json, dict) and parsed_json.get("action") == "run_command":
                                cmd = parsed_json.get("shell_command")
                                if cmd:
                                    logger.info(f"Executing JSON Command Action: {cmd}")
                                    from tools.code_tools import exec_shell_command
                                    result_dict = exec_shell_command(cmd)
                                    
                                    if result_dict.get("returncode") == 0:
                                        output_val = result_dict.get("stdout")
                                        # If empty, say so
                                        if not output_val: output_val = "Command executed successfully (no output)."
                                    else:
                                        logger.error(f"Command failed: {result_dict.get('stderr')}")
                                        output_val = f"Error: {result_dict.get('stderr')}"
                                else:
                                    # Valid JSON but no command?
                                    output_val = parsed_json
                            else:
                                # Just normal JSON data
                                output_val = parsed_json
                        except Exception as e:
                            logger.warning(f"Failed to parse JSON content: {e}. Keeping raw string.")
                            pass
            
            # If output_val is still None at this point (and we didn't recover)
            if output_val is None and (step.save_output_to_context_key is None or step.save_output_to_context_key not in self.context):
                 output_val = "Error: Step execution failed or returned no content."
                 if step.save_output_to_context_key:
                     self.context[step.save_output_to_context_key] = output_val

            # Fail-fast: Raise exception if step resulted in error
            if output_val and isinstance(output_val, str) and output_val.startswith("Error"):
                error_msg = output_val
                logger.error(f"Step '{step.step_name}' failed with error: {error_msg}")
                raise RuntimeError(f"Step '{step.step_name}' failed: {error_msg}")

            if output_val is not None: # Check if output_val was set or recovered
                logger.info(f"Step Result: {output_val}")
                if step.save_output_to_context_key and step.save_output_to_context_key not in self.context: # Only save if not already saved by recovery
                    self.context[step.save_output_to_context_key] = output_val

            # Log to Persistent Memory
            if output_val:
                self.memory_store.log_step(
                    scenario_name=scenario.name,
                    step_name=step.step_name,
                    agent_name=step.agent_name,
                    input_text=instruction,
                    output_text=output_val
                )

            logger.info(f"--- Step '{step.step_name}' Complete ---\n")
            
            logger.info(f"--- Step '{step.step_name}' Complete ---\n")

        logger.info("Scenario Execution Complete.")
        return self.context
