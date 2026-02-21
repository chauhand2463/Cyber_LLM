"""
Compatibility layer for pyautogen (autogen)
Provides unified API for the CyberLLM framework
"""

import sys
import os

# Try importing from pyautogen first (new package name)
try:
    import pyautogen
    from pyautogen import ConversableAgent, UserProxyAgent, AssistantAgent
    from pyautogen import GroupChat, GroupChatManager
    
    try:
        from pyautogen import runtime_logging
    except ImportError:
        runtime_logging = getattr(pyautogen, 'runtime_logging', None)
    
    AUTOGEN_AVAILABLE = True
    AUTOGEN_VERSION = "pyautogen"
    
except ImportError:
    # Fallback to old autogen package
    try:
        import autogen
        from autogen import ConversableAgent, UserProxyAgent, AssistantAgent
        from autogen import GroupChat, GroupChatManager
        runtime_logging = getattr(autogen, 'runtime_logging', None)
        AUTOGEN_AVAILABLE = True
        AUTOGEN_VERSION = "autogen"
        
    except ImportError:
        # No autogen available - use mock
        AUTOGEN_AVAILABLE = False
        AUTOGEN_VERSION = "mock"
        runtime_logging = None
        
        class ConversableAgent:
            def __init__(self, name, llm_config=None, **kwargs):
                self.name = name
                self.llm_config = llm_config
                self.kwargs = kwargs
                self._messages = []
                
            def send(self, message, recipient, request_reply=False, silent=False):
                print(f"[{self.name} -> {recipient.name}]: {message}")
                
            def receive(self, message, sender, request_reply=False, silent=False):
                self._messages.append({'content': message, 'sender': sender.name})
                
            def register_for_llm(self, name=None, description=None):
                def decorator(func):
                    return func
                return decorator
                
            def register_for_execution(self, name=None):
                def decorator(func):
                    return func
                return decorator
                
            def initiate_chat(self, recipient, message=None, **kwargs):
                print(f"[{self.name} initiating chat with {recipient.name}]: {message}")
                return None
                
            def initiate_chats(self, chat_requests):
                print(f"[{self.name}] Initiating {len(chat_requests)} chats")
                return None

        class UserProxyAgent(ConversableAgent):
            pass
            
        class AssistantAgent(ConversableAgent):
            pass
            
        class GroupChat:
            def __init__(self, agents=None, messages=None, max_round=10):
                self.agents = agents or []
                self.messages = messages or []
                self.max_round = max_round
                
        class GroupChatManager(ConversableAgent):
            def __init__(self, groupchat=None, llm_config=None, **kwargs):
                super().__init__("groupchat_manager", llm_config, **kwargs)
                self.groupchat = groupchat


def register_function(func, caller, executor, name=None, description=None):
    """Register a function to be called by agents."""
    if not AUTOGEN_AVAILABLE:
        print(f"Mock register_function: {name}")
        return
        
    try:
        if hasattr(caller, 'register_for_llm'):
            caller.register_for_llm(name=name, description=description)(func)
        if hasattr(executor, 'register_for_execution'):
            executor.register_for_execution(name=name)(func)
    except Exception as e:
        print(f"Warning: Could not register function {name}: {e}")


__all__ = [
    'ConversableAgent', 'UserProxyAgent', 'AssistantAgent',
    'GroupChat', 'GroupChatManager', 'runtime_logging',
    'register_function', 'AUTOGEN_AVAILABLE', 'AUTOGEN_VERSION'
]
