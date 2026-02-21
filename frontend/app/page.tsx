import MissionControl from "@/components/MissionControl";
import { Cpu, Wifi } from "lucide-react";

export default function Home() {
  return (
    <main className="p-8">
      {/* Top Bar */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-4xl font-rajdhani font-black text-white tracking-widest uppercase">
            Cybernetic <span className="text-cyber-cyan">Command</span> Console
          </h1>
          <p className="text-gray-400 font-rajdhani tracking-wider mt-1">
            ADVANCED AGENT ORCHESTRATION SYSTEM // V.2.0.4
          </p>
        </div>

        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2 text-cyber-cyan animate-pulse">
            <Wifi size={20} />
            <span className="font-mono text-sm">UPLINK_ESTABLISHED</span>
          </div>
          <div className="flex items-center gap-2 text-cyber-red">
            <Cpu size={20} />
            <span className="font-mono text-sm">CORE_ONLINE</span>
          </div>
        </div>
      </div>

      {/* Control Surface */}
      <MissionControl />
    </main>
  );
}
