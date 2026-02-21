import asyncio
import sys
import io
import contextlib
from agents import text_agents, caldera_agents, code_agents
from agents.text_agents import task_coordinator_agent
import actions.agent_actions
import autogen_compat as autogen
from utils.shared_config import clean_working_directory

# We need to capture stdout to stream it via WebSocket
class StreamCapture:
    def __init__(self, queue: asyncio.Queue):
        self.queue = queue

    def write(self, text):
        # We put the text into the queue to be consumed by the websocket
        if text.strip(): # Avoid sending just empty newlines validation
             asyncio.create_task(self.queue.put({"type": "log", "content": text}))

    def flush(self):
        pass

class AgentService:
    @staticmethod
    def init_agents():
        # Clean directories
        clean_working_directory("/caldera")
        clean_working_directory("/pdf")
        clean_working_directory("/code")
        
        # Register tools (idempotent if handled correctly, but we call it just in case)
        text_agents.register_tools()
        code_agents.register_tools()

    @staticmethod
    def retrieve_agent(agent_name):
        if agent_name == "caldera_agent":
            return caldera_agents.caldera_agent
        elif agent_name == "internet_agent":
            return text_agents.internet_agent
        elif agent_name == "text_analyst_agent":
            return text_agents.text_analyst_agent
        elif agent_name == "cmd_exec_agent":
            return code_agents.cmd_exec_agent
        else:
            return None

    @staticmethod
    async def run_scenario_stream(scenario_name: str, queue: asyncio.Queue):
        """
        Runs a scenario and streams the output to the queue.
        This runs the synchronous autogen code in a separate thread.
        """
        AgentService.init_agents()
        
        scenario_agents = []
        scenario_tasks = []

        if scenario_name not in actions.agent_actions.scenarios:
             await queue.put({"type": "error", "content": f"Scenario {scenario_name} not found"})
             return

        scenario_action_names = actions.agent_actions.scenarios[scenario_name]

        for scenario_action_name in scenario_action_names:
            for scenario_action in actions.agent_actions.actions[scenario_action_name]:
                scenario_agents.append(scenario_action["agent"])
                
                scenario_task = {
                    "recipient": AgentService.retrieve_agent(scenario_action["agent"]),
                    "message": scenario_action["message"],
                    "silent": False,
                }

                if "clear_history" in scenario_action:
                    scenario_task["clear_history"] = scenario_action["clear_history"]
                else:
                    scenario_task["clear_history"] = True

                if "summary_prompt" in scenario_action:
                    scenario_task["summary_prompt"] = scenario_action["summary_prompt"]

                if "summary_method" in scenario_action:
                    scenario_task["summary_method"] = scenario_action["summary_method"]

                if "carryover" in scenario_action:
                    scenario_task["carryover"] = scenario_action["carryover"]

                scenario_tasks.append(scenario_task)

        # Capture list of tasks to run
        tasks_to_run = scenario_tasks

        # Helper function to run the blocking code
        def _run_blocking(main_loop):
            import traceback
            from autogen.io import IOStream
            from typing import Any, Optional
            
            # CRITICAL FIX: Set a new event loop for this thread so libraries > 
            # (like Autogen or internal async calls) don't crash when checking for one.
            try:
                thread_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(thread_loop)
            except Exception:
                pass # Best effort

            # Define a concrete IOStream implementation for WebSockets
            class WebSocketIO:
                def __init__(self, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
                    self.queue = queue
                    self.loop = loop

                def print(self, *objects: Any, sep: str = " ", end: str = "\n", flush: bool = False) -> None:
                    # Construct message
                    text = sep.join(map(str, objects)) + end
                    if text.strip():
                        # Use the MAIN LOOP to schedule the queue put, as queue is bound to it
                        asyncio.run_coroutine_threadsafe(
                            self.queue.put({"type": "log", "content": text}),
                            self.loop
                        )

                def input(self, prompt: str = "", password: bool = False) -> str:
                    return ""

            # Capture stdout/stderr (legacy support)
            capture = StreamCapture(queue)
            original_stdout = sys.stdout
            sys.stdout = capture
            
            # Capture Autogen IOStream
            original_iostream = IOStream.get_default()
            new_iostream = WebSocketIO(queue, main_loop)
            IOStream.set_default(new_iostream)
            
            try:
                print(f"DEBUG: Starting scenario {scenario_name} with {len(tasks_to_run)} tasks")
                # We do not use logging_session_id here to simplify
                task_coordinator_agent.initiate_chats(tasks_to_run)
                print("DEBUG: Scenario finished successfully")
            except Exception as e:
                error_msg = f"CRITICAL AGENT ERROR: {str(e)}\n{traceback.format_exc()}"
                print(error_msg) 
                asyncio.run_coroutine_threadsafe(
                    queue.put({"type": "error", "content": error_msg}),
                    main_loop
                )
                sys.stderr.write(error_msg + "\n")
            finally:
                # Restore everything
                IOStream.set_default(original_iostream)
                sys.stdout = original_stdout
                # Close the thread loop
                try:
                    thread_loop.close()
                except:
                    pass

        # Run in executor
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _run_blocking, loop)
        except Exception as e:
            await queue.put({"type": "error", "content": f"Executor Error: {e}"})
        
        await queue.put({"type": "end", "content": "Mission Completed"})
