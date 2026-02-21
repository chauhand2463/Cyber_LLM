from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from actions.agent_actions import scenarios
import asyncio
import uuid
from typing import List, Dict

app = FastAPI(title="CyberSecurity Agent Mission Control")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development convenience
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/scenarios")
async def list_scenarios() -> Dict[str, List[str]]:
    """List all available mission scenarios."""
    return {
        "scenarios": list(scenarios.keys())
    }

@app.get("/api/health")
async def health_check():
    return {"status": "online", "system": "Cybernetic Command Console"}

from services.agent_runner import AgentService

@app.websocket("/api/ws/run/{scenario_id}")
async def websocket_endpoint(websocket: WebSocket, scenario_id: str):
    await websocket.accept()
    queue = asyncio.Queue()
    
    # Start the agent runner in a background task
    runner_task = asyncio.create_task(
        AgentService.run_scenario_stream(scenario_id, queue)
    )

    try:
        while True:
            # Get messages from the queue
            data = await queue.get()
            
            # Send to websocket
            await websocket.send_json(data)
            
            # If end of stream
            if data["type"] == "end":
                break
                
    except Exception as e:
        await websocket.send_json({"type": "error", "content": str(e)})
    finally:
        await websocket.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
