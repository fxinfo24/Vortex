import { useState } from 'react';
import axios from 'axios';
import { Network, Radio, Activity, ShieldAlert, Cpu, Skull } from 'lucide-react';

// Add props interface
interface WiresharkPanelProps {
    initialFilter?: string;
    onLog?: (msg: string) => void;
}

export default function WiresharkPanel({ initialFilter = '', onLog }: WiresharkPanelProps) {
    const [activeTab, setActiveTab] = useState<'map' | 'capture' | 'analyze' | 'redteam'>('capture');
    const [subnet, setSubnet] = useState('172.18.0.0/24'); // Default smaller subnet for speed
    const [loading, setLoading] = useState(false);
    const [results, setResults] = useState<any>(null);
    const [logs, setLogs] = useState<string[]>([]);
    const [displayFilter, setDisplayFilter] = useState(initialFilter);

    // Red Team Props
    const [targetIp, setTargetIp] = useState('172.18.0.2');
    const [gatewayIp, setGatewayIp] = useState('172.18.0.1');
    const [pcapPath, setPcapPath] = useState('');
    const [keyPath, setKeyPath] = useState('');

    // Sync logs to parent if provided, else local.
    const addLog = (msg: string) => {
        const fullMsg = `[${new Date().toLocaleTimeString()}] ${msg}`;
        setLogs(prev => [fullMsg, ...prev]);
        if (onLog) onLog(fullMsg);
    };

    const handleDecrypt = async () => {
        setLoading(true);
        addLog(`Decrypting ${pcapPath} with ${keyPath}...`);
        try {
            const res = await axios.post('/api/net/decrypt', { pcap_path: pcapPath, key_path: keyPath });
            addLog(`Decryption success. Output: ${res.data.file}`);
        } catch (e: any) {
            addLog(`Decryption Error: ${e.message}`);
        } finally {
            setLoading(false);
        }
    }


    const handleNetworkScan = async () => {
        setLoading(true);
        setResults(null);
        addLog(`Starting network map scan on ${subnet}...`);
        try {
            const res = await axios.post('/api/net/scan', { subnet });
            setResults({ type: 'map', data: res.data });
            addLog(`Scan complete. Found ${res.data.length} devices.`);
        } catch (e: any) {
            addLog(`Error: ${e.message}`);
        } finally {
            setLoading(false);
        }
    };

    const handleCapture = async () => {
        setLoading(true);
        setResults(null);
        addLog(`Starting packet capture (5s) with filter: ${displayFilter || 'none'}...`);
        try {
            const res = await axios.post('/api/net/capture', { duration: 5, count: 50, filter: displayFilter });
            setResults({ type: 'capture', data: res.data });
            addLog(`Capture complete. Captured ${res.data.length} packets.`);
        } catch (e: any) {
            addLog(`Error: ${e.message}`);
        } finally {
            setLoading(false);
        }
    };

    const handleAnalyze = async () => {
        setLoading(true);
        setResults(null);
        addLog("Analyzing traffic for sensitive data...");
        try {
            const res = await axios.post('/api/net/analyze');
            setResults({ type: 'analyze', data: res.data });
            addLog("Analysis complete.");
        } catch (e: any) {
            addLog(`Error: ${e.message}`);
        } finally {
            setLoading(false);
        }
    };

    const handleInject = async () => {
        try {
            await axios.post('/api/net/inject', { target: '172.18.0.1', port: 80, count: 5 });
            addLog("Injected 5 test packets to gateway.");
        } catch (e: any) {
            addLog(`Injection failed: ${e.message}`);
        }
    }

    const handleMitm = async () => {
        setLoading(true);
        addLog(`Starting MITM (ARP Spoof) between ${targetIp} and ${gatewayIp}...`);
        try {
            await axios.post('/api/net/mitm', { target: targetIp, gateway: gatewayIp, duration: 10 });
            addLog("MITM Attack Cycle Complete.");
        } catch (e: any) {
            addLog(`MITM Error: ${e.message}`);
        } finally {
            setLoading(false);
        }
    }

    const handleDos = async () => {
        setLoading(true);
        addLog(`Starting DoS Flood on ${targetIp}...`);
        try {
            await axios.post('/api/net/dos', { target: targetIp, port: 80, duration: 10 });
            addLog("DoS Attack Cycle Complete.");
        } catch (e: any) {
            addLog(`DoS Error: ${e.message}`);
        } finally {
            setLoading(false);
        }
    }

    const handlePromisc = async () => {
        setLoading(true);
        addLog("Enabling Promiscuous Mode on interface...");
        try {
            await axios.post('/api/net/promisc');
            addLog("Success: Promiscuous Mode Enabled.");
        } catch (e: any) {
            addLog(`Error: ${e.response?.data?.detail || e.message}`);
        } finally {
            setLoading(false);
        }
    }

    return (
        <div className="space-y-6">
            {/* Tabs */}
            <div className="flex gap-2 border-b border-white/10 pb-4 overflow-x-auto">
                <button
                    onClick={() => setActiveTab('capture')}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors whitespace-nowrap ${activeTab === 'capture' ? 'bg-[#00f0ff]/20 text-[#00f0ff]' : 'text-gray-400 hover:bg-white/5'}`}
                >
                    <Radio className="w-4 h-4" />
                    Packet Capture
                </button>
                <button
                    onClick={() => setActiveTab('map')}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors whitespace-nowrap ${activeTab === 'map' ? 'bg-[#00f0ff]/20 text-[#00f0ff]' : 'text-gray-400 hover:bg-white/5'}`}
                >
                    <Network className="w-4 h-4" />
                    Network Map
                </button>
                <button
                    onClick={() => setActiveTab('analyze')}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors whitespace-nowrap ${activeTab === 'analyze' ? 'bg-[#00f0ff]/20 text-[#00f0ff]' : 'text-gray-400 hover:bg-white/5'}`}
                >
                    <ShieldAlert className="w-4 h-4" />
                    Secret Hunter
                </button>
                <button
                    onClick={() => setActiveTab('redteam')}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors whitespace-nowrap ${activeTab === 'redteam' ? 'bg-red-600/20 text-red-500' : 'text-gray-400 hover:bg-white/5'}`}
                >
                    <Skull className="w-4 h-4" />
                    Red Team
                </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Controls Panel */}
                <div className="glass-panel p-6 space-y-6 h-fit">
                    <h3 className="text-lg font-bold text-gray-200 flex items-center gap-2">
                        <Activity className="w-5 h-5 text-[#00f0ff]" />
                        Control Center
                    </h3>

                    {activeTab === 'map' && (
                        <div className="space-y-4">
                            <div className="space-y-2">
                                <label className="text-xs uppercase text-gray-500 font-mono">Subnet</label>
                                <input
                                    value={subnet}
                                    onChange={e => setSubnet(e.target.value)}
                                    className="input-field"
                                />
                                <p className="text-[10px] text-gray-500">Tip: Use /24 for faster scans.</p>
                            </div>
                            <button onClick={handleNetworkScan} disabled={loading} className="btn-primary w-full">
                                {loading ? 'Scanning...' : 'Start Mapper'}
                            </button>
                        </div>
                    )}

                    {activeTab === 'capture' && (
                        <div className="space-y-4 tab-capture">
                            <p className="text-sm text-gray-400">Capture live traffic from the container interface.</p>
                            <div className="space-y-2">
                                <label className="text-xs uppercase text-gray-500 font-mono">Display Filter</label>
                                <input
                                    value={displayFilter}
                                    onChange={e => setDisplayFilter(e.target.value)}
                                    placeholder="tcp.port == 80"
                                    className="input-field font-mono text-xs"
                                />
                            </div>
                            <button onClick={handleCapture} disabled={loading} className="btn-primary w-full">
                                {loading ? 'Capturing...' : 'Start Capture (5s)'}
                            </button>
                            <button onClick={handleInject} className="w-full py-2 px-4 rounded bg-red-500/10 text-red-500 border border-red-500/20 hover:bg-red-500/20 transition-colors text-sm">
                                Inject Test Packets
                            </button>
                        </div>
                    )}

                    {activeTab === 'analyze' && (
                        <div className="space-y-4">
                            <p className="text-sm text-gray-400">Analyze traffic for sensitive patterns (passwords, tokens, cookies).</p>
                            <button onClick={handleAnalyze} disabled={loading} className="btn-primary w-full bg-yellow-500/80 hover:bg-yellow-500">
                                {loading ? 'Hunting...' : 'Start Analysis'}
                            </button>
                        </div>
                    )}

                    {activeTab === 'redteam' && (
                        <div className="space-y-4 border-l-2 border-red-600 pl-4">
                            <h4 className="text-red-500 font-mono text-xs uppercase mb-2">Advanced Operations</h4>
                            <div className="space-y-2">
                                <label className="text-xs uppercase text-gray-500 font-mono">Target IP</label>
                                <input value={targetIp} onChange={e => setTargetIp(e.target.value)} className="input-field border-red-900 focus:border-red-600" />
                            </div>
                            <div className="space-y-2">
                                <label className="text-xs uppercase text-gray-500 font-mono">Gateway IP</label>
                                <input value={gatewayIp} onChange={e => setGatewayIp(e.target.value)} className="input-field border-red-900 focus:border-red-600" />
                            </div>

                            <div className="grid grid-cols-2 gap-2 mt-4">
                                <button onClick={handleMitm} disabled={loading} className="p-3 bg-red-600 hover:bg-red-500 rounded text-black font-bold text-xs">
                                    Start MITM
                                </button>
                                <button onClick={handleDos} disabled={loading} className="p-3 border border-red-600 text-red-600 hover:bg-red-600/10 rounded font-bold text-xs">
                                    Launch DoS
                                </button>
                            </div>

                            <hr className="border-red-900/30 my-4" />

                            <h4 className="text-red-500 font-mono text-xs uppercase mb-2">SSL Decryption</h4>
                            <div className="space-y-2">
                                <label className="text-xs uppercase text-gray-500 font-mono">PCAP Path</label>
                                <input value={pcapPath} onChange={e => setPcapPath(e.target.value)} className="input-field border-red-900 focus:border-red-600" placeholder="/app/capture.pcap" />
                            </div>
                            <div className="space-y-2">
                                <label className="text-xs uppercase text-gray-500 font-mono">Key Path</label>
                                <input value={keyPath} onChange={e => setKeyPath(e.target.value)} className="input-field border-red-900 focus:border-red-600" placeholder="/app/ssl.keys" />
                            </div>
                            <button onClick={handleDecrypt} disabled={loading} className="w-full mt-2 p-2 bg-red-900/30 text-red-400 border border-red-900 rounded hover:bg-red-900/50 text-xs">
                                Decrypt Traffic
                            </button>

                            <hr className="border-red-900/30 my-4" />

                            <button onClick={handlePromisc} disabled={loading} className="w-full p-2 bg-red-900/30 text-red-400 border border-red-900 rounded hover:bg-red-900/50 text-xs font-mono uppercase tracking-wider">
                                Enable Promiscuous Mode
                            </button>
                        </div>
                    )}

                    {/* Mini Log Console */}
                    <div className="bg-black/40 rounded-lg p-3 font-mono text-[10px] text-gray-400 h-32 overflow-y-auto border border-white/5">
                        {logs.map((l, i) => <div key={i}>{l}</div>)}
                        {logs.length === 0 && <span className="opacity-50">System ready...</span>}
                    </div>
                </div>

                {/* Results Panel */}
                <div className="lg:col-span-2 glass-panel p-6 min-h-[400px]">
                    {!results && !loading && (
                        <div className="h-full flex flex-col items-center justify-center text-gray-500">
                            <div className="p-4 bg-white/5 rounded-full mb-4">
                                {activeTab === 'redteam' ? <Skull className="w-8 h-8 text-red-600" /> : <Cpu className="w-8 h-8 opacity-50" />}
                            </div>
                            <p>{activeTab === 'redteam' ? "WARNING: Authorized Testing Only" : "Waiting for operation..."}</p>
                        </div>
                    )}

                    {loading && (
                        <div className="h-full flex flex-col items-center justify-center text-[#00f0ff]">
                            <div className={`w-8 h-8 border-2 border-current border-t-transparent rounded-full animate-spin mb-4 ${activeTab === 'redteam' ? 'text-red-500' : ''}`} />
                            <p className="animate-pulse">Processing Operation...</p>
                        </div>
                    )}

                    {results && results.type === 'capture' && (
                        <div className="space-y-4 overflow-x-auto">
                            <h4 className="font-bold text-[#00f0ff] mb-4">Packet Capture Results</h4>
                            <table className="w-full text-left font-mono text-xs">
                                <thead>
                                    <tr className="border-b border-white/10 text-gray-500">
                                        <th className="p-2">Time</th>
                                        <th className="p-2">Proto</th>
                                        <th className="p-2">Source</th>
                                        <th className="p-2">Dest</th>
                                        <th className="p-2">Info</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {results.data.map((pkt: any, i: number) => (
                                        <tr key={i} className="border-b border-white/5 hover:bg-white/5">
                                            <td className="p-2 text-gray-400">
                                                {(() => {
                                                    if (!pkt.timestamp) return 'N/A';
                                                    const ts = parseFloat(pkt.timestamp);
                                                    if (isNaN(ts)) return 'Invalid';
                                                    return new Date(ts * 1000).toLocaleTimeString();
                                                })()}
                                            </td>
                                            <td className="p-2 text-yellow-500">{pkt.protocol}</td>
                                            <td className="p-2 text-blue-400">{pkt.source}</td>
                                            <td className="p-2 text-blue-400">{pkt.destination}</td>
                                            <td className="p-2 text-gray-300 truncate max-w-[200px]">{pkt.info}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}

                    {results && results.type === 'map' && (
                        <div className="space-y-4">
                            <h4 className="font-bold text-[#00f0ff] mb-4">Network Devices</h4>
                            <div className="grid gap-3">
                                {results.data.map((dev: any, i: number) => (
                                    <div key={i} className="flex justify-between items-center bg-white/5 p-3 rounded border border-white/10">
                                        <span className="font-mono text-lg text-white">{dev.ip}</span>
                                        <span className="font-mono text-sm text-gray-500">{dev.mac}</span>
                                    </div>
                                ))}
                                {results.data.length === 0 && <p>No devices found (or permission denied).</p>}
                            </div>
                        </div>
                    )}

                    {results && results.type === 'analyze' && (
                        <div className="space-y-4">
                            <h4 className="font-bold text-yellow-500 mb-4">Sensitive Data Report</h4>
                            <div className="space-y-6">
                                <div>
                                    <h5 className="text-sm uppercase text-gray-500 mb-2">Credentials Found</h5>
                                    {results.data.credentials.length > 0 ? (
                                        results.data.credentials.map((c: string, i: number) => <div key={i} className="bg-red-500/10 text-red-400 p-2 rounded">{c}</div>)
                                    ) : <div className="text-gray-600 italic">None found</div>}
                                </div>
                                <div>
                                    <h5 className="text-sm uppercase text-gray-500 mb-2">Cookies</h5>
                                    {results.data.cookies.length > 0 ? (
                                        results.data.cookies.map((c: string, i: number) => <div key={i} className="bg-orange-500/10 text-orange-400 p-2 rounded truncate">{c}</div>)
                                    ) : <div className="text-gray-600 italic">None found</div>}
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
