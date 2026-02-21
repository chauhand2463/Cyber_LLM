import type { Metadata } from "next";
import { JetBrains_Mono, Rajdhani } from "next/font/google";
import "./globals.css";

const rajdhani = Rajdhani({
  variable: "--font-rajdhani",
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700"],
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "MISSION CONTROL | Cyber LLM Agents",
  description: "Advanced Cyber Security Agent Orchestration",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${rajdhani.variable} ${jetbrainsMono.variable} antialiased min-h-screen bg-cyber-void text-foreground selection:bg-cyber-cyan selection:text-black`}
      >
        <div className="scanlines" />
        <div className="relative z-10">
          {children}
        </div>
      </body>
    </html>
  );
}
