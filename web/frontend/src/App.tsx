import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal, Activity, Shield, Zap, Search, ChevronRight, Server, AlertCircle, Radio } from 'lucide-react';
import axios from 'axios';
import clsx from 'clsx';
import WiresharkPanel from './WiresharkPanel';

// Types
type ScanType = 'syn' | 'udp' | 'comprehensive' | 'vulnerability';
type AppMode = 'nmap' | 'wireshark';

function App() {
  const [mode, setMode] = useState<AppMode>('nmap');
  const [target, setTarget] = useState('');
  const [ports, setPorts] = useState('1-1000');
  const [scanType, setScanType] = useState<ScanType>('syn');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [generatedFilter, setGeneratedFilter] = useState('');

  const handleAnalyzeInWireshark = async () => {
    if (!result) return;
    try {
      const res = await axios.post('/api/utils/nmap-to-filter', result);
      setGeneratedFilter(res.data.filter);
      setMode('wireshark');
    } catch (e: any) {
      console.error("Filter generation failed", e);
      setMode('wireshark');
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await axios.post('/scan', {
        target,
        ports,
        scan_type: scanType,
        timing: 4
      });
      setResult(response.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  const getScanIcon = (type: ScanType) => {
    switch (type) {
      case 'syn': return <Zap className="w-5 h-5" />;
      case 'udp': return <Activity className="w-5 h-5" />;
      case 'comprehensive': return <Search className="w-5 h-5" />;
      case 'vulnerability': return <Shield className="w-5 h-5" />;
    }
  };

  return (
    <div className="min-h-screen bg-[#050505] text-gray-200 font-sans selection:bg-[#00f0ff] selection:text-black">
      <div className="fixed inset-0 cyber-grid opacity-30 pointer-events-none" />

      <div className="max-w-6xl mx-auto px-6 py-12 relative z-10">
        {/* Header */}
        <motion.header
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-12 text-center"
        >
          <div className="inline-flex items-center justify-center p-3 bg-[#00f0ff]/10 rounded-2xl mb-6 ring-1 ring-[#00f0ff]/20">
            <img src="/logo.png" alt="Vortex" className="w-12 h-12 object-contain" />
          </div>
          <h1 className="text-4xl md:text-5xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white via-gray-200 to-gray-500 mb-4 tracking-tight">
            Vortex
          </h1>
          <p className="text-gray-500 max-w-lg mx-auto text-lg mb-8">
            Advanced network reconnaissance and vulnerability assessment interface.
          </p>

          {/* Mode Switcher */}
          <div className="inline-flex p-1 bg-white/5 rounded-xl border border-white/10">
            <button
              onClick={() => setMode('nmap')}
              className={clsx(
                "px-6 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2",
                mode === 'nmap' ? "bg-[#00f0ff] text-black shadow-lg shadow-[#00f0ff]/20" : "text-gray-400 hover:text-white"
              )}
            >
              <Terminal className="w-4 h-4" />
              Nmap Scanner
            </button>
            <button
              onClick={() => setMode('wireshark')}
              className={clsx(
                "px-6 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2",
                mode === 'wireshark' ? "bg-[#00f0ff] text-black shadow-lg shadow-[#00f0ff]/20" : "text-gray-400 hover:text-white"
              )}
            >
              <Radio className="w-4 h-4" />
              Wireshark Suite
            </button>
          </div>
        </motion.header>

        {mode === 'wireshark' ? (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <WiresharkPanel initialFilter={generatedFilter} />
          </motion.div>
        ) : (
          <div className="grid lg:grid-cols-12 gap-8">
            {/* Controls */}
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.1 }}
              className="lg:col-span-4"
            >
              <form onSubmit={handleScan} className="glass-panel p-6 space-y-6 sticky top-8">
                <div className="space-y-2">
                  <label className="text-xs font-mono text-gray-400 uppercase tracking-widest">Target Host</label>
                  <div className="relative">
                    <Server className="absolute left-3 top-3 text-gray-500 w-5 h-5" />
                    <input
                      type="text"
                      value={target}
                      onChange={(e) => setTarget(e.target.value)}
                      placeholder="192.168.1.1 or CIDR"
                      className="input-field pl-10"
                      required
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="text-xs font-mono text-gray-400 uppercase tracking-widest">Port Range</label>
                  <input
                    type="text"
                    value={ports}
                    onChange={(e) => setPorts(e.target.value)}
                    placeholder="e.g. 1-1000, 80,443"
                    className="input-field"
                  />
                </div>

                <div className="space-y-3">
                  <label className="text-xs font-mono text-gray-400 uppercase tracking-widest">Scan Profile</label>
                  <div className="grid grid-cols-2 gap-3">
                    {(['syn', 'udp', 'comprehensive', 'vulnerability'] as ScanType[]).map((type) => (
                      <button
                        key={type}
                        type="button"
                        onClick={() => setScanType(type)}
                        className={clsx(
                          "flex items-center gap-2 p-3 rounded-lg border text-sm font-medium transition-all",
                          scanType === type
                            ? "bg-[#00f0ff]/10 border-[#00f0ff] text-[#00f0ff]"
                            : "bg-transparent border-white/10 text-gray-400 hover:border-white/20 hover:text-gray-300"
                        )}
                      >
                        {getScanIcon(type)}
                        <span className="capitalize">{type === 'comprehensive' ? 'Full' : type}</span>
                      </button>
                    ))}
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="btn-primary w-full shadow-lg shadow-[#00f0ff]/20"
                >
                  {loading ? (
                    <>
                      <Activity className="w-5 h-5 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <Terminal className="w-5 h-5" />
                      Start Scan
                    </>
                  )}
                </button>
              </form>
            </motion.div>

            {/* Results Output */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.2 }}
              className="lg:col-span-8 space-y-6"
            >
              {error && (
                <div className="bg-[#ff003c]/10 border border-[#ff003c]/20 p-4 rounded-xl flex items-start gap-3">
                  <AlertCircle className="w-6 h-6 text-[#ff003c] shrink-0" />
                  <div>
                    <h3 className="text-[#ff003c] font-bold">Scan Error</h3>
                    <p className="text-gray-400 text-sm mt-1">{error}</p>
                  </div>
                </div>
              )}

              {!result && !loading && !error && (
                <div className="glass-panel h-[400px] flex flex-col items-center justify-center text-center p-8 border-dashed">
                  <div className="w-20 h-20 rounded-full bg-white/5 flex items-center justify-center mb-6">
                    <Search className="w-8 h-8 text-gray-600" />
                  </div>
                  <h3 className="text-xl font-medium text-gray-300 mb-2">Ready to Scan</h3>
                  <p className="text-gray-500 max-w-sm">
                    Configure your target and parameters on the left to begin the reconnaissance operation.
                  </p>
                </div>
              )}

              {loading && (
                <div className="glass-panel h-[400px] flex flex-col items-center justify-center relative overflow-hidden">
                  <div className="absolute inset-0 bg-[#00f0ff]/5 animate-pulse" />
                  <div className="w-16 h-16 border-4 border-[#00f0ff]/30 border-t-[#00f0ff] rounded-full animate-spin mb-6" />
                  <h3 className="text-xl font-medium text-[#00f0ff] animate-pulse">Scanning Target...</h3>
                  <p className="text-gray-500 mt-2 font-mono text-sm">Executing Nmap operations</p>
                </div>
              )}

              {result && (
                <AnimatePresence>
                  <div className="space-y-6">
                    {/* Summary Cards */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      {Object.entries(result).map(([ip]) => (
                        <div key={ip} className="glass-panel p-4 border-l-4 border-l-[#00ff9f]">
                          <div className="text-xs text-gray-500 uppercase font-mono mb-1">Host</div>
                          <div className="text-lg font-bold">{ip}</div>
                        </div>
                      ))}
                      <div className="glass-panel p-4">
                        <div className="text-xs text-gray-500 uppercase font-mono mb-1">Status</div>
                        <div className="text-lg font-bold text-[#00ff9f]">Online</div>
                      </div>

                      {/* Integration Action */}
                      <button
                        onClick={handleAnalyzeInWireshark}
                        className="glass-panel p-4 hover:bg-[#00f0ff]/10 cursor-pointer transition-colors border-dashed border-[#00f0ff]/30 text-left group"
                      >
                        <div className="text-xs text-[#00f0ff] uppercase font-mono mb-1 flex items-center gap-1">
                          <Zap className="w-3 h-3 group-hover:rotate-12 transition-transform" />
                          Next Step
                        </div>
                        <div className="text-sm font-bold text-gray-300 group-hover:text-white">Analyze in Wireshark →</div>
                      </button>
                    </div>

                    {/* Main Results Data */}
                    {Object.entries(result).map(([ip, data]: [string, any]) => (
                      <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        key={ip}
                        className="glass-panel overflow-hidden"
                      >
                        <div className="px-6 py-4 border-b border-white/5 bg-white/5 flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <Server className="w-5 h-5 text-gray-400" />
                            <span className="font-mono font-bold text-lg">{ip}</span>
                          </div>
                          {data.hostname && (
                            <span className="text-sm text-gray-500 bg-black/30 px-3 py-1 rounded-full border border-white/5">
                              {data.hostname}
                            </span>
                          )}
                        </div>

                        <div className="p-6">
                          {/* Iterate protocols (tcp, udp) */}
                          {['tcp', 'udp'].map(proto => {
                            if (!data[proto]) return null;
                            return (
                              <div key={proto} className="mb-6 last:mb-0">
                                <h4 className="text-sm font-mono text-[#00f0ff] uppercase mb-4 flex items-center gap-2">
                                  <ChevronRight className="w-4 h-4" />
                                  {proto} Protocol
                                </h4>

                                <div className="overflow-x-auto">
                                  <table className="w-full text-left border-collapse">
                                    <thead>
                                      <tr className="border-b border-white/10 text-xs text-gray-500 uppercase">
                                        <th className="py-3 px-4 font-normal w-24">Port</th>
                                        <th className="py-3 px-4 font-normal w-24">State</th>
                                        <th className="py-3 px-4 font-normal">Service</th>
                                        <th className="py-3 px-4 font-normal">Version</th>
                                      </tr>
                                    </thead>
                                    <tbody className="font-mono text-sm">
                                      {Object.entries(data[proto]).map(([port, info]: [string, any]) => (
                                        <tr key={port} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                                          <td className="py-3 px-4 text-[#00f0ff]">{port}</td>
                                          <td className="py-3 px-4">
                                            <span className={clsx(
                                              "px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider",
                                              info.state === 'open' ? "bg-[#00ff9f]/10 text-[#00ff9f]" : "bg-gray-800 text-gray-400"
                                            )}>
                                              {info.state}
                                            </span>
                                          </td>
                                          <td className="py-3 px-4 text-gray-300">{info.name || 'unknown'}</td>
                                          <td className="py-3 px-4 text-gray-500 truncate max-w-[200px]">
                                            {info.product} {info.version}
                                          </td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                </div>
                              </div>
                            );
                          })}

                          {/* Check for empty results */}
                          {!data.tcp && !data.udp && (
                            <div className="text-center py-12 text-gray-500">
                              No open ports found or host blocked scans.
                            </div>
                          )}
                        </div>
                      </motion.div>
                    ))}
                  </div>
                </AnimatePresence>
              )}

              {/* Raw JSON Debug (Collapsed) */}
              {result && (
                <details className="group">
                  <summary className="list-none text-xs font-mono text-gray-600 cursor-pointer hover:text-[#00f0ff] transition-colors flex items-center justify-center gap-2 mt-8">
                    <span>VIEW RAW DATA</span>
                  </summary>
                  <div className="mt-4 p-4 bg-black rounded-xl border border-white/10 overflow-x-auto">
                    <pre className="text-[10px] text-gray-500 font-mono">
                      {JSON.stringify(result, null, 2)}
                    </pre>
                  </div>
                </details>
              )}

            </motion.div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
