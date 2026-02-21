'use client';

import { getScenarios } from "@/lib/api";
import { clsx } from "clsx";
import { Activity, ChevronRight, Play, Shield } from "lucide-react";
import { useEffect, useState } from "react";
import TerminalLog from "./TerminalLog";

interface LogEntry {
    type: "log" | "error" | "end" | "info";
    content: string;
    timestamp: number;
}

export default function MissionControl() {
    const [scenarios, setScenarios] = useState<string[]>([]);
    const [selectedScenario, setSelectedScenario] = useState<string | null>(null);
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [status, setStatus] = useState<"idle" | "running" | "completed" | "error">("idle");
    const [ws, setWs] = useState<WebSocket | null>(null);

    // Fetch scenarios on mount
    useEffect(() => {
        getScenarios().then(setScenarios);
    }, []);

    // Cleanup websocket
    useEffect(() => {
        return () => {
            if (ws) ws.close();
        };
    }, [ws]);

    const runScenario = (scenarioId: string) => {
        if (status === "running") return; // Prevent multiple runs

        // Reset state
        setLogs([]);
        setStatus("running");
        setSelectedScenario(scenarioId);

        // Connect WebSocket
        const socket = new WebSocket(`ws://localhost:8000/api/ws/run/${scenarioId}`);

        socket.onopen = () => {
            setLogs(prev => [...prev, { type: "info", content: `CONNECTED TO AGENT SWARM: ${scenarioId}`, timestamp: Date.now() }]);
        };

        socket.onmessage = (event) => {
            const data = JSON.parse(event.data);
            setLogs(prev => [...prev, { ...data, timestamp: Date.now() }]);

            if (data.type === "end" || data.type === "error") {
                setStatus(data.type === "error" ? "error" : "completed");
                socket.close();
            }
        };

        socket.onerror = (error) => {
            console.error("WS Error", error);
            setLogs(prev => [...prev, { type: "error", content: "WEBSOCKET CONNECTION FAILURE", timestamp: Date.now() }]);
            setStatus("error");
        };

        socket.onclose = () => {
            // Only set to completed if not already error
        };

        setWs(socket);
    };

    return (
        <div className="grid grid-cols-12 gap-6 h-[calc(100vh-8rem)]">
            {/* Sidebar: Scenarios */}
            <div className="col-span-3 bg-cyber-panel/50 border border-cyber-cyan/20 rounded-lg p-4 flex flex-col backdrop-blur-sm">
                <div className="flex items-center gap-2 mb-6 text-cyber-cyan">
                    <Shield size={24} />
                    <h2 className="font-rajdhani font-bold text-xl tracking-wider">AVAILABLE_MISSIONS</h2>
                </div>

                <div className="flex-1 overflow-y-auto space-y-2 pr-2">
                    {scenarios.map((scenario) => (
                        <button
                            key={scenario}
                            onClick={() => setSelectedScenario(scenario)}
                            className={clsx(
                                "w-full text-left p-3 rounded font-rajdhani tracking-wide transition-all border",
                                selectedScenario === scenario
                                    ? "bg-cyber-cyan/10 border-cyber-cyan text-cyber-cyan shadow-[0_0_10px_rgba(0,243,255,0.2)]"
                                    : "bg-black/40 border-transparent text-gray-400 hover:bg-cyber-cyan/5 hover:text-white hover:border-cyber-cyan/30"
                            )}
                        >
                            <div className="flex items-center justify-between">
                                <span className="truncate">{scenario}</span>
                                {selectedScenario === scenario && <ChevronRight size={16} />}
                            </div>
                        </button>
                    ))}
                </div>

                {/* Action Area */}
                <div className="pt-4 border-t border-white/10 mt-4">
                    <button
                        onClick={() => selectedScenario && runScenario(selectedScenario)}
                        disabled={!selectedScenario || status === "running"}
                        className={clsx(
                            "w-full py-3 px-4 rounded font-bold font-rajdhani tracking-widest uppercase flex items-center justify-center gap-2 transition-all",
                            !selectedScenario ? "bg-gray-800 text-gray-500 cursor-not-allowed" :
                                status === "running" ? "bg-amber-500/20 text-amber-500 border border-amber-500 animate-pulse cursor-wait" :
                                    "bg-cyber-cyan text-black hover:bg-white hover:shadow-[0_0_20px_rgba(0,243,255,0.6)]"
                        )}
                    >
                        {status === "running" ? (
                            <>
                                <Activity size={20} className="animate-spin" />
                                EXEC_IN_PROGRESS
                            </>
                        ) : (
                            <>
                                <Play size={20} />
                                ENGAGE_AGENTS
                            </>
                        )}
                    </button>
                </div>
            </div>

            {/* Main Content: Terminal */}
            <div className="col-span-9">
                <TerminalLog logs={logs} status={status} />
            </div>
        </div>
    );
}
