import { useState, useEffect, useRef } from 'react';
import { Terminal, Shield, Activity, FileJson, Mail, Database, Github, Download } from 'lucide-react';
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Line, Pie } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

interface LogEntry {
  timestamp: string;
  protocol: string;
  src_ip: string;
  dst_ip: string;
  description: string;
  severity: string;
}

function App() {
  const [isSimulating, setIsSimulating] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const logDisplayRef = useRef<HTMLDivElement>(null);
  
  // Simulated packet analysis data
  const simulatePacketAnalysis = () => {
    if (!isSimulating) return;

    const protocols = ['HTTP', 'DNS', 'ICMP'];
    let protocol = protocols[Math.floor(Math.random() * protocols.length)];
    const src_ip = `192.168.1.${Math.floor(Math.random() * 255)}`;
    const dst_ip = `192.168.1.${Math.floor(Math.random() * 255)}`;
    
    let description = '';
    let severity = 'INFO';
    
    switch (protocol) {
      case 'HTTP':
        description = 'HTTP packet detected';
        break;
      case 'DNS':
        description = 'DNS query detected';
        break;
      case 'ICMP':
        description = 'ICMP packet detected';
        break;
    }

    // Randomly generate alerts
    if (Math.random() < 0.1) {
      const suspiciousPort = Math.random() < 0.5 ? 22 : 3389;
      description = `Suspicious port ${suspiciousPort} access`;
      severity = 'CRITICAL';
      protocol = 'ALERT';
    }

    const newLog: LogEntry = {
      timestamp: new Date().toISOString(),
      protocol,
      src_ip,
      dst_ip,
      description,
      severity,
    };

    setLogs(prevLogs => [...prevLogs, newLog].slice(-100)); // Keep last 100 logs
  };

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isSimulating) {
      interval = setInterval(simulatePacketAnalysis, 1000);
    }
    return () => clearInterval(interval);
  }, [isSimulating]);

  useEffect(() => {
    if (logDisplayRef.current) {
      logDisplayRef.current.scrollTop = logDisplayRef.current.scrollHeight;
    }
  }, [logs]);

  const getProtocolColor = (protocol: string) => {
    switch (protocol) {
      case 'HTTP': return 'text-green-400';
      case 'DNS': return 'text-purple-400';
      case 'ICMP': return 'text-yellow-400';
      case 'ALERT': return 'text-red-400';
      default: return 'text-blue-400';
    }
  };

  const pieChartData = {
    labels: ['HTTP', 'DNS', 'ICMP', 'ALERT'],
    datasets: [{
      data: [
        logs.filter(log => log.protocol === 'HTTP').length,
        logs.filter(log => log.protocol === 'DNS').length,
        logs.filter(log => log.protocol === 'ICMP').length,
        logs.filter(log => log.protocol === 'ALERT').length,
      ],
      backgroundColor: ['#00ff9d', '#ff00c3', '#ffd700', '#ff6b6b'],
      borderColor: '#23272a',
      borderWidth: 2,
    }],
  };

  const timelineData = {
    labels: logs.slice(-20).map(log => new Date(log.timestamp).toLocaleTimeString()),
    datasets: [{
      label: 'Incidents',
      data: logs.slice(-20).map((_, index) => index + 1),
      borderColor: '#00ff9d',
      backgroundColor: 'rgba(0, 255, 157, 0.2)',
      tension: 0.4,
    }],
  };

  return (
    <div className="min-h-screen bg-black text-white font-mono">
      {/* Navbar */}
      <nav className="fixed top-0 w-full bg-black/90 backdrop-blur-sm border-b border-green-500/20 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Shield className="w-6 h-6 text-green-500" />
            <span className="text-xl font-bold">PyIDS Pro</span>
          </div>
          <div className="flex space-x-6">
            <a href="#features" className="hover:text-green-400 transition-colors">Features</a>
            <a href="#Demo" className="hover:text-green-400 transition-colors">Live Demo</a>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-4">
        <div className="container mx-auto text-center">
          <div className="inline-block animate-pulse bg-green-500/20 rounded-full px-4 py-1 mb-6">
            <span className="text-green-400">v3.0 Now Available</span>
          </div>
          <h1 className="text-5xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-green-400 via-blue-500 to-purple-600 text-transparent bg-clip-text">
            Real-Time Intrusion Detection Made Simple
          </h1>
          <p className="text-gray-400 text-xl mb-8 max-w-2xl mx-auto">
            Advanced packet sniffing, protocol filtering, and automated alerts. Built for security professionals who demand precision.
          </p>
          <div className="flex flex-wrap justify-center gap-4">
              <a href="/files/IDevSec-v3.0.zip" download>
                <Button size="lg" className="bg-green-500 hover:bg-green-600">
                  <Download className="mr-2 h-5 w-5" /> Download Now
                </Button>
              </a>
                <a
                href="https://github.com/Shivam-Kadam86/PyIDSPro"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Button size="lg" variant="outline" className="border-green-500 text-green-500 hover:bg-green-500/10">
                  <Github className="mr-2 h-5 w-5" /> View Source
                </Button>
              </a>
            </div>
        </div>
      </section>


      {/* Features Grid */}
      <section id="features" className="py-20 bg-black/50">
        <div className="container mx-auto px-4">
          <h2 className="text-3xl font-bold text-center mb-12">
            Powerful Features for Advanced Security
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            <FeatureCard
              icon={<Terminal className="w-8 h-8 text-green-500" />}
              title="Real-Time Packet Sniffing"
              description="Monitor HTTP, DNS, ICMP traffic with instant threat detection and analysis."
            />
            <FeatureCard
              icon={<Activity className="w-8 h-8 text-blue-500" />}
              title="Visual Analytics"
              description="Interactive protocol charts and incident timeline visualization."
            />
            <FeatureCard
              icon={<Mail className="w-8 h-8 text-purple-500" />}
              title="Automated Alerts"
              description="Instant email notifications with detailed threat information."
            />
            <FeatureCard
              icon={<FileJson className="w-8 h-8 text-yellow-500" />}
              title="PDF Reports"
              description="Generate comprehensive security reports with one click."
            />
            <FeatureCard
              icon={<Database className="w-8 h-8 text-red-500" />}
              title="SQLite Logging"
              description="Efficient storage and filtering of security events."
            />
            <FeatureCard
              icon={<Shield className="w-8 h-8 text-green-500" />}
              title="Advanced Protection"
              description="Custom rules and intelligent threat detection algorithms."
            />
          </div>
        </div>
      </section>

      {/* Live Demo Section */}
      <section id="Demo"className="py-20 bg-black">
        <div className="container mx-auto px-4">
          <div className="max-w-6xl mx-auto">
            <h2 className="text-3xl font-bold text-center mb-12">Live Demo</h2>
            
            {/* Terminal Window */}
            <div className="bg-gray-900 rounded-lg p-4 mb-8">
              <div className="flex items-center mb-4">
                <div className="w-3 h-3 rounded-full bg-red-500 mr-2"></div>
                <div className="w-3 h-3 rounded-full bg-yellow-500 mr-2"></div>
                <div className="w-3 h-3 rounded-full bg-green-500"></div>
              </div>
              <div 
                ref={logDisplayRef}
                className="h-64 overflow-y-auto font-mono text-sm space-y-2"
              >
                {logs.map((log, index) => (
                  <div key={index} className={getProtocolColor(log.protocol)}>
                    [{log.protocol}] {log.src_ip} → {log.dst_ip}: {log.description}
                  </div>
                ))}
              </div>
            </div>

            {/* Controls */}
            <div className="text-center mb-12">
              <Button
                onClick={() => setIsSimulating(!isSimulating)}
                className={`${
                  isSimulating ? 'bg-red-500 hover:bg-red-600' : 'bg-green-500 hover:bg-green-600'
                }`}
              >
                {isSimulating ? 'Stop Simulation' : 'Start Simulation'}
              </Button>
            </div>

            {/* Charts */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <Card className="p-6 bg-gray-900/50">
                <h3 className="text-xl font-bold mb-4">Protocol Distribution</h3>
                <div className="h-64">
                  <Pie data={pieChartData} options={{
                    plugins: {
                      legend: {
                        labels: {
                          color: '#fff'
                        }
                      }
                    }
                  }} />
                </div>
              </Card>
              
              <Card className="p-6 bg-gray-900/50">
                <h3 className="text-xl font-bold mb-4">Incident Timeline</h3>
                <div className="h-64">
                  <Line data={timelineData} options={{
                    plugins: {
                      legend: {
                        labels: {
                          color: '#fff'
                        }
                      }
                    },
                    scales: {
                      x: {
                        ticks: { color: '#fff' }
                      },
                      y: {
                        ticks: { color: '#fff' }
                      }
                    }
                  }} />
                </div>
              </Card>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

function FeatureCard({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) {
  return (
    <Card className="p-6 bg-gray-900/50 border-gray-800 hover:border-green-500/50 transition-all duration-300">
      <div className="mb-4">{icon}</div>
      <h3 className="text-xl font-bold mb-2">{title}</h3>
      <p className="text-gray-400">{description}</p>
    </Card>
  );
}

export default App;
