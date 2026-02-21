'use client';

import { clsx } from "clsx";
import { AnimatePresence, motion } from "framer-motion";
import { CheckCircle, Cpu, ShieldAlert, Terminal } from "lucide-react";
import { useEffect, useRef, useState } from "react";

interface LogEntry {
    type: "log" | "error" | "end" | "info";
    content: string;
    timestamp: number;
}

interface TerminalLogProps {
    logs: LogEntry[];
    status: "idle" | "running" | "completed" | "error";
    className?: string;
}

export default function TerminalLog({ logs, status, className }: TerminalLogProps) {
    const scrollRef = useRef<HTMLDivElement>(null);
    const [autoScroll, setAutoScroll] = useState(true);

    useEffect(() => {
        if (autoScroll && scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [logs, autoScroll]);

    return (
        <div className={clsx("flex flex-col h-full bg-cyber-void border border-cyber-cyan/30 rounded-lg overflow-hidden shadow-[0_0_20px_rgba(0,243,255,0.1)]", className)}>
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-2 bg-cyber-panel border-b border-cyber-cyan/20">
                <div className="flex items-center gap-2 text-cyber-cyan">
                    <Terminal size={18} />
                    <span className="font-rajdhani font-bold tracking-wider text-sm">AGENT_OUTPUT_STREAM</span>
                </div>
                <div className="flex items-center gap-2">
                    <div className={clsx("w-2 h-2 rounded-full animate-pulse",
                        status === "running" ? "bg-cyber-cyan" :
                            status === "error" ? "bg-cyber-red" :
                                status === "completed" ? "bg-green-500" : "bg-gray-500"
                    )} />
                    <span className="text-xs uppercase tracking-widest text-opacity-70 text-white font-mono">{status}</span>
                </div>
            </div>

            {/* Logs Area */}
            <div
                ref={scrollRef}
                onScroll={(e) => {
                    const bottom = e.currentTarget.scrollHeight - e.currentTarget.scrollTop === e.currentTarget.clientHeight;
                    setAutoScroll(bottom);
                }}
                className="flex-1 p-4 overflow-y-auto font-mono text-sm space-y-1 scroll-smooth"
            >
                <AnimatePresence>
                    {logs.length === 0 && (
                        <div className="h-full flex flex-col items-center justify-center text-gray-500 space-y-4 opacity-50">
                            <Cpu size={48} className="animate-pulse" />
                            <p className="font-rajdhani tracking-widest">SYSTEM_READY // AWAITING_指令</p>
                        </div>
                    )}
                    {logs.map((log, index) => (
                        <motion.div
                            key={index}
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ duration: 0.2 }}
                            className={clsx(
                                "break-words whitespace-pre-wrap leading-relaxed",
                                log.type === "error" ? "text-cyber-red" :
                                    log.type === "end" ? "text-green-400 font-bold border-t border-b border-green-500/30 py-2 my-2" :
                                        "text-cyber-cyan/90"
                            )}
                        >
                            <span className="opacity-40 mr-2 select-none">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                            {log.type === "error" && <ShieldAlert size={14} className="inline mr-1" />}
                            {log.type === "end" && <CheckCircle size={14} className="inline mr-1" />}
                            {log.content}
                        </motion.div>
                    ))}
                </AnimatePresence>

                {/* Cursor Blinking */}
                {status === "running" && (
                    <motion.div
                        animate={{ opacity: [0, 1, 0] }}
                        transition={{ repeat: Infinity, duration: 0.8 }}
                        className="w-2 h-4 bg-cyber-cyan mt-1"
                    />
                )}
            </div>
        </div>
    );
}
