from typing_extensions import Annotated
import json
from engine.memory_store import MemoryStore

def query_memory(
    query: Annotated[str, "The search term to look for in past execution logs"],
    limit: Annotated[int, "The maximum number of results to return"] = 5
) -> Annotated[str, "JSON string containing the search results"]:
    """
    Search the persistent memory (past executions) for a specific term.
    Useful for retrieving results from previous scenarios or tasks.
    """
    store = MemoryStore()
    results = store.query_logs(query, limit)
    
    if not results:
        return json.dumps({"message": "No matching records found."})
    
    return json.dumps({"results": results}, indent=2)
