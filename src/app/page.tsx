'use client';

import { Shield, Search, AlertTriangle, CheckCircle, Lock } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent } from "@/components/ui/card"
import Link from "next/link"
import { useState, useEffect, ChangeEvent } from "react"

interface Analytics {
  urlsScanned: number;
  threatDetectionRate: number;
  protectedUsers: number;
  lastUpdated: string;
}

interface ScanStats {
  totalScans: number;
  safeScans: number;
  unsafeScans: number;
  safetyRate: string;
  topThreats: Array<{ _id: string; count: number }>;
  recentScans: Array<{
    url: string;
    isSafe: boolean;
    scannedAt: string;
  }>;
}

interface SecurityCheckDetails {
  isTyposquatting?: boolean;
  isLookalike?: boolean;
  isFakeSubdomain?: boolean;
  isIPAddress?: boolean;
  hasHTTPS?: boolean;
  hasSuspiciousQuery?: boolean;
  hasRedirect?: boolean;
  hasSuspiciousPatterns?: boolean;
  hasSubstitutions?: boolean;
  issues?: string[];
  [key: string]: boolean | string[] | undefined;
}

interface GoogleSafetyResult {
  safe: boolean;
  threats: Array<{
    type: string;
    platform?: string;
    severity?: string;
    timestamp?: string;
  }>;
  message: string;
}

interface SecurityChecksResult {
  safe: boolean;
  threats: string[];
  details: {
    [key: string]: SecurityCheckDetails;
  };
}

interface ScanResult {
  safe: boolean;
  message: string;
  details?: {
    securityChecks: SecurityChecksResult;
    googleSafety: GoogleSafetyResult;
  };
}

interface Statistics {
  totalScans: number;
  safeScans: number;
  unsafeScans: number;
  detectionRate: number;
  threatDistribution: Array<{ threat_type: string; count: number }>;
  protectedUsers: number;
  recentScans: Array<{
    url: string;
    is_safe: boolean;
    scan_date: string;
  }>;
  lastUpdated: string;
}

const API_BASE_URL = 'http://localhost:8080/api';

export default function HomePage() {
  const [url, setUrl] = useState("")
  const [scanning, setScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState<{ stage: string; accuracy: number } | null>(null)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [analytics, setAnalytics] = useState<Analytics | null>(null)
  const [scanStats, setScanStats] = useState<ScanStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [serverStatus, setServerStatus] = useState<'checking' | 'online' | 'offline'>('checking')
  const [error, setError] = useState<string | null>(null)

  const handleLogoClick = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
    setUrl("");
    setResult(null);
    setError(null);
    setScanProgress(null);
  };

  // Check server status on mount and periodically
  useEffect(() => {
    let intervalId: NodeJS.Timeout;
    let retryCount = 0;
    const maxRetries = 3;

    const checkServerStatus = async () => {
      try {
        console.log('Checking server status...');
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        const response = await fetch(`${API_BASE_URL}/health`, {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
          },
          credentials: 'include',
          mode: 'cors',
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (response.ok) {
          const data = await response.json();
          console.log('Server health check response:', data);
          
          if (data.database?.connected && 
              data.database?.sessionTable && 
              data.database?.usersTable && 
              data.apiKeyConfigured) {
            setServerStatus('online');
            retryCount = 0;
          } else {
            console.error('Server components not fully initialized:', data);
            setServerStatus('offline');
            retryCount++;
          }
        } else {
          console.error('Server health check failed:', response.status);
          setServerStatus('offline');
          retryCount++;
        }
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
        console.error('Server status check failed:', errorMessage);
        if (err instanceof Error && err.name === 'AbortError') {
          console.log('Request timed out');
        }
        setServerStatus('offline');
        retryCount++;
      }

      // If we've reached max retries, increase the check interval
      if (retryCount >= maxRetries) {
        if (intervalId) {
          clearInterval(intervalId);
        }
        intervalId = setInterval(checkServerStatus, 30000); // Check every 30 seconds after max retries
      }
    };

    // Check immediately
    checkServerStatus();

    // Then check every 5 seconds initially
    intervalId = setInterval(checkServerStatus, 5000);

    return () => {
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }, []);

  // Fetch analytics and stats data
  useEffect(() => {
    let retryCount = 0;
    const maxRetries = 3;
    const baseDelay = 2000; // 2 seconds base delay

    const fetchData = async () => {
      if (serverStatus !== 'online') {
        console.log('Server is not online, skipping data fetch');
        return;
      }
      
      try {
        console.log('Fetching analytics and stats data...');
        
        // Fetch statistics with timeout
        const statsController = new AbortController();
        const statsTimeout = setTimeout(() => statsController.abort(), 10000);
        
        const statsResponse = await fetch(`${API_BASE_URL}/statistics`, {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
          },
          credentials: 'include',
          mode: 'cors',
          signal: statsController.signal
        });
        clearTimeout(statsTimeout);

        if (!statsResponse.ok) {
          const errorData = await statsResponse.json().catch(() => ({}));
          throw new Error(errorData.message || `Stats fetch failed: ${statsResponse.status}`);
        }

        const statsData = await statsResponse.json();
        console.log('Fetched statistics:', statsData);

        // Ensure we have valid statistics data
        if (!statsData?.statistics) {
          throw new Error('Invalid statistics data received');
        }

        const stats: Statistics = statsData.statistics;

        // Calculate detection rate if not provided
        const detectionRate = stats.detectionRate !== undefined 
          ? Number(stats.detectionRate) 
          : stats.totalScans > 0 
            ? (stats.unsafeScans / stats.totalScans * 100)
            : 0;

        // Update analytics state with safe type checking
        setAnalytics({
          urlsScanned: Number(stats.totalScans) || 0,
          threatDetectionRate: detectionRate,
          protectedUsers: Number(stats.protectedUsers) || 0,
          lastUpdated: stats.lastUpdated || new Date().toISOString()
        });

        // Update scan stats state with safe type checking
        const safetyRate = (100 - detectionRate).toFixed(1);

        setScanStats({
          totalScans: Number(stats.totalScans) || 0,
          safeScans: Number(stats.safeScans) || 0,
          unsafeScans: Number(stats.unsafeScans) || 0,
          safetyRate: safetyRate,
          topThreats: Array.isArray(stats.threatDistribution) 
            ? stats.threatDistribution.map(threat => ({
                _id: String(threat.threat_type || ''),
                count: Number(threat.count) || 0
              }))
            : [],
          recentScans: Array.isArray(stats.recentScans)
            ? stats.recentScans.map(scan => ({
                url: String(scan.url || ''),
                isSafe: Boolean(scan.is_safe),
                scannedAt: String(scan.scan_date || new Date().toISOString())
              }))
            : []
        });

        retryCount = 0; // Reset retry count on success
        setError(null); // Clear any previous errors
      } catch (error) {
        console.error('Failed to fetch data:', error);
        
        // Handle different types of errors
        if (error instanceof Error) {
          if (error.name === 'AbortError') {
            console.log('Request timed out, retrying...');
            setError('Request timed out. Retrying...');
          } else {
            setError(error.message);
          }
        } else {
          setError('An unexpected error occurred');
        }

        retryCount++;
        
        if (retryCount < maxRetries) {
          // Exponential backoff: 2s, 4s, 8s
          const delay = baseDelay * Math.pow(2, retryCount - 1);
          console.log(`Retrying data fetch (${retryCount}/${maxRetries}) in ${delay}ms...`);
          setTimeout(fetchData, delay);
        } else {
          console.log('Max retries reached for data fetch');
          // Set default values
          setAnalytics({
            urlsScanned: 0,
            threatDetectionRate: 0,
            protectedUsers: 0,
            lastUpdated: new Date().toISOString()
          });
          setScanStats({
            totalScans: 0,
            safeScans: 0,
            unsafeScans: 0,
            safetyRate: '0.0',
            topThreats: [],
            recentScans: []
          });
          setError('Failed to fetch data after multiple attempts. Please try again later.');
        }
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, [serverStatus]);

  const handleScan = async () => {
    if (!url) {
      setError("Please enter a URL to scan");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);
    setScanning(true);
    setScanProgress({ stage: "Initializing scan...", accuracy: 0 });

    try {
      // First check server status with timeout
      const healthController = new AbortController();
      const healthTimeout = setTimeout(() => healthController.abort(), 10000);
      
      setScanProgress({ stage: "Checking server status...", accuracy: 10 });
      
      const healthResponse = await fetch(`${API_BASE_URL}/health`, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
        },
        signal: healthController.signal
      });
      clearTimeout(healthTimeout);

      if (!healthResponse.ok) {
        throw new Error('Server is not responding');
      }

      setScanProgress({ stage: "Performing security checks...", accuracy: 30 });

      // Then proceed with scan with timeout
      const scanController = new AbortController();
      const scanTimeout = setTimeout(() => scanController.abort(), 15000); // 15 second timeout for scan
      
      const response = await fetch(`${API_BASE_URL}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          'Accept': 'application/json',
        },
        body: JSON.stringify({ url }),
        signal: scanController.signal
      });
      clearTimeout(scanTimeout);

      setScanProgress({ stage: "Analyzing results...", accuracy: 70 });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || data.error || "Failed to scan URL");
      }

      setScanProgress({ stage: "Finalizing scan...", accuracy: 90 });
      
      // Transform the response data to match our ScanResult interface
      const scanResult: ScanResult = {
        safe: data.safe,
        message: data.message,
        details: {
          securityChecks: {
            safe: data.details?.securityChecks?.safe ?? true,
            threats: data.details?.securityChecks?.threats ?? [],
            details: data.details?.securityChecks?.details ?? {}
          },
          googleSafety: {
            safe: data.details?.googleSafety?.safe ?? true,
            threats: data.details?.googleSafety?.threats ?? [],
            message: data.details?.googleSafety?.message ?? "No Google Safe Browsing data available"
          }
        }
      };
      
      setResult(scanResult);

      // Immediately update analytics with the data from the scan response
      if (data.analytics) {
        console.log('Updating analytics with:', data.analytics);
        setAnalytics(data.analytics);
        
        // Also update scan stats with timeout
        try {
          const statsController = new AbortController();
          const statsTimeout = setTimeout(() => statsController.abort(), 10000);
          
          const statsResponse = await fetch(`${API_BASE_URL}/analytics/stats`, {
            method: 'GET',
            headers: {
              'Accept': 'application/json',
            },
            signal: statsController.signal
          });
          clearTimeout(statsTimeout);
          
          if (statsResponse.ok) {
            const statsData = await statsResponse.json();
            console.log('Updating scan stats with:', statsData);
            setScanStats(statsData);
          }
        } catch (statsError) {
          console.error('Failed to update scan stats:', statsError);
        }
      }

      setScanProgress({ stage: "Scan complete!", accuracy: 100 });
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'An unknown error occurred';
      setError(errorMessage);
      setResult({
        safe: false,
        message: errorMessage
      });
    } finally {
      setLoading(false);
      setScanning(false);
      setScanProgress(null);
    }
  };

  const handleUrlChange = (e: ChangeEvent<HTMLInputElement>) => {
    setUrl(e.target.value);
  };

  const formatNumber = (num: number) => {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M+';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K+';
    return num.toString();
  };

  // Show server status in the UI
  const renderServerStatus = () => {
    if (serverStatus === 'checking') {
      return <div className="text-yellow-400">Checking server status...</div>;
    }
    if (serverStatus === 'offline') {
      return <div className="text-red-400">Server is offline. Please make sure the server is running.</div>;
    }
    return null;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      {/* Navigation */}
      <nav className="border-b border-white/10 backdrop-blur-sm bg-white/5">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div 
              className="flex items-center space-x-2 cursor-pointer hover:opacity-80 transition-opacity"
              onClick={handleLogoClick}
            >
              <Shield className="h-8 w-8 text-blue-400" />
              <span className="text-2xl font-bold text-white">NetSafeScan</span>
            </div>
            <div className="flex items-center space-x-4">
              <Link href="/login">
                <Button variant="ghost" className="text-white hover:bg-white/10 cursor-pointer">
                  Login
                </Button>
              </Link>
              <Link href="/signup">
                <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer">Sign Up</Button>
              </Link>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative overflow-hidden">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-16">
          <div className="text-center">
            <h1 className="text-5xl md:text-7xl font-bold text-white mb-6">
              Protect Yourself from
              <span className="bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
                {" "}
                Scams & Phishing
              </span>
            </h1>
            <p className="text-xl text-gray-300 mb-12 max-w-3xl mx-auto">
              Advanced real-time URL scanning to detect malicious websites, phishing attempts, and scams before they
              can harm you or your business.
            </p>

            {/* URL Scanner */}
            <div className="max-w-2xl mx-auto mb-16">
              <Card className="bg-white/10 backdrop-blur-sm border-white/20">
                <CardContent className="p-6">
                  {renderServerStatus()}
                  <div className="flex flex-col sm:flex-row gap-4">
                    <div className="flex-1">
                      <Input
                        placeholder="Enter URL to scan (e.g., https://example.com)"
                        className="bg-white/10 border-white/20 text-white placeholder:text-gray-400 h-12 text-lg"
                        value={url}
                        onChange={handleUrlChange}
                      />
                    </div>
                    <Button
                      className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 h-12 px-8"
                      onClick={handleScan}
                      disabled={scanning || serverStatus !== 'online'}
                    >
                      <Search className="w-5 h-5 mr-2" />
                      {scanning ? 'Scanning...' : 'Scan URL'}
                    </Button>
                  </div>
                  {scanProgress && (
                    <div className="mt-4 space-y-2">
                      <div className="text-sm text-gray-300">{scanProgress.stage}</div>
                      <div className="w-full bg-gray-700 rounded-full h-2.5">
                        <div
                          className="bg-blue-600 h-2.5 rounded-full transition-all duration-300"
                          style={{ width: `${scanProgress.accuracy}%` }}
                        ></div>
                      </div>
                      <div className="flex justify-between items-center text-sm">
                        <span className="text-gray-400">Scan Progress</span>
                        <span className="text-blue-400 font-medium">{scanProgress.accuracy}%</span>
                      </div>
                      <div className="flex justify-between items-center text-sm">
                        <span className="text-gray-400">Threat Detection</span>
                        <span className="text-red-400 font-medium">Active</span>
                      </div>
                      <div className="text-xs text-gray-500 mt-1">
                        Real-time threat detection using advanced security algorithms
                      </div>
                    </div>
                  )}
                  {result && (
                    <div className={`mt-4 p-6 rounded-lg ${result.safe ? 'bg-green-500/20 border border-green-500/30' : 'bg-red-500/20 border border-red-500/30'}`}>
                      <div className="flex items-start space-x-4">
                        {result.safe ? (
                          <CheckCircle className="h-8 w-8 text-green-400 flex-shrink-0 mt-1" />
                        ) : (
                          <AlertTriangle className="h-8 w-8 text-red-400 flex-shrink-0 mt-1" />
                        )}
                        <div className="flex-1">
                          <h3 className={`text-xl font-semibold ${result.safe ? 'text-green-400' : 'text-red-400'} mb-2`}>
                            {result.safe ? 'URL is Safe' : 'URL is Potentially Dangerous'}
                          </h3>
                          <p className="text-white mb-4">{result.message}</p>
                          
                          {result.details && (
                            <div className="space-y-4">
                              {result.safe ? (
                                // Safe URL Information
                                <div className="bg-black/20 p-4 rounded-lg">
                                  <h4 className="text-lg font-medium text-white mb-3">Safety Analysis</h4>
                                  <div className="space-y-4">
                                    {/* Security Checks */}
                                    {result.details.securityChecks && (
                                      <div className="space-y-2">
                                        <h5 className="text-md font-medium text-green-400">Security Checks Passed</h5>
                                        <ul className="space-y-2">
                                          {Object.entries(result.details.securityChecks.details).map(([key, value]: [string, SecurityCheckDetails]) => {
                                            if (!value.isTyposquatting && !value.isLookalike && !value.isFakeSubdomain && 
                                                !value.isIPAddress && value.hasHTTPS && !value.hasSuspiciousQuery && 
                                                !value.hasRedirect && !value.hasSuspiciousPatterns && !value.hasSubstitutions) {
                                              return (
                                                <li key={key} className="flex items-center space-x-2 text-gray-300">
                                                  <CheckCircle className="h-5 w-5 text-green-400 flex-shrink-0" />
                                                  <span className="capitalize">{key.replace(/([A-Z])/g, ' $1').trim()}</span>
                                                </li>
                                              );
                                            }
                                            return null;
                                          })}
                                        </ul>
                                      </div>
                                    )}

                                    {/* Google Safe Browsing */}
                                    {result.details.googleSafety && result.details.googleSafety.safe && (
                                      <div className="space-y-2">
                                        <h5 className="text-md font-medium text-green-400">Google Safe Browsing</h5>
                                        <div className="flex items-center space-x-2 text-gray-300">
                                          <CheckCircle className="h-5 w-5 text-green-400 flex-shrink-0" />
                                          <span>{result.details.googleSafety.message}</span>
                                        </div>
                                      </div>
                                    )}

                                    {/* Safety Recommendations */}
                                    <div className="mt-4">
                                      <h5 className="text-md font-medium text-green-400 mb-2">Safety Status</h5>
                                      <ul className="space-y-2 text-gray-300">
                                        <li className="flex items-center space-x-2">
                                          <CheckCircle className="h-5 w-5 text-green-400 flex-shrink-0" />
                                          <span>This URL has passed all security checks</span>
                                        </li>
                                        <li className="flex items-center space-x-2">
                                          <CheckCircle className="h-5 w-5 text-green-400 flex-shrink-0" />
                                          <span>No suspicious patterns or threats detected</span>
                                        </li>
                                        <li className="flex items-center space-x-2">
                                          <CheckCircle className="h-5 w-5 text-green-400 flex-shrink-0" />
                                          <span>Safe to proceed with normal browsing</span>
                                        </li>
                                      </ul>
                                    </div>
                                  </div>
                                </div>
                              ) : (
                                // Dangerous URL Information
                                <div className="bg-black/20 p-4 rounded-lg">
                                  <h4 className="text-lg font-medium text-white mb-3">Risk Analysis</h4>
                                  <div className="space-y-4">
                                    {/* Security Checks */}
                                    {result.details.securityChecks && (
                                      <div className="space-y-2">
                                        <h5 className="text-md font-medium text-red-400">Security Issues Detected</h5>
                                        <ul className="space-y-2">
                                          {Object.entries(result.details.securityChecks.details).map(([key, value]: [string, SecurityCheckDetails]) => {
                                            if (value.isTyposquatting || value.isLookalike || value.isFakeSubdomain || 
                                                value.isIPAddress || !value.hasHTTPS || value.hasSuspiciousQuery || 
                                                value.hasRedirect || value.hasSuspiciousPatterns || value.hasSubstitutions) {
                                              return (
                                                <li key={key} className="flex items-start space-x-2">
                                                  <AlertTriangle className="h-5 w-5 text-red-400 flex-shrink-0 mt-1" />
                                                  <div>
                                                    <span className="text-white capitalize">{key.replace(/([A-Z])/g, ' $1').trim()}</span>
                                                    {value.issues && value.issues.length > 0 && (
                                                      <ul className="list-disc list-inside text-gray-300 text-sm mt-1">
                                                        {value.issues.map((issue: string, index: number) => (
                                                          <li key={index}>{issue}</li>
                                                        ))}
                                                      </ul>
                                                    )}
                                                  </div>
                                                </li>
                                              );
                                            }
                                            return null;
                                          })}
                                        </ul>
                                      </div>
                                    )}

                                    {/* Google Safe Browsing */}
                                    {result.details.googleSafety && !result.details.googleSafety.safe && (
                                      <div className="space-y-2">
                                        <h5 className="text-md font-medium text-red-400">Google Safe Browsing Warnings</h5>
                                        <div className="space-y-2">
                                          <p className="text-white">{result.details.googleSafety.message}</p>
                                          {result.details.googleSafety.threats && result.details.googleSafety.threats.length > 0 && (
                                            <div className="mt-2">
                                              <p className="text-gray-300 text-sm mb-2">Detected Threats:</p>
                                              <ul className="list-disc list-inside text-gray-300 text-sm">
                                                {result.details.googleSafety.threats.map((threat: {
                                                  type: string;
                                                  platform?: string;
                                                  severity?: string;
                                                  timestamp?: string;
                                                }, index: number) => (
                                                  <li key={index} className="flex items-center space-x-2">
                                                    <span className="text-red-400">•</span>
                                                    <span>{threat.type}</span>
                                                  </li>
                                                ))}
                                              </ul>
                                            </div>
                                          )}
                                        </div>
                                      </div>
                                    )}

                                    {/* Risk Recommendations */}
                                    <div className="mt-4">
                                      <h5 className="text-md font-medium text-red-400 mb-2">Risk Assessment</h5>
                                      <ul className="space-y-2 text-gray-300">
                                        <li className="flex items-center space-x-2">
                                          <AlertTriangle className="h-5 w-5 text-red-400 flex-shrink-0" />
                                          <span>Exercise extreme caution when visiting this URL</span>
                                        </li>
                                        <li className="flex items-center space-x-2">
                                          <AlertTriangle className="h-5 w-5 text-red-400 flex-shrink-0" />
                                          <span>Don&apos;t enter any personal or sensitive information</span>
                                        </li>
                                        <li className="flex items-center space-x-2">
                                          <AlertTriangle className="h-5 w-5 text-red-400 flex-shrink-0" />
                                          <span>Consider using a secure browser or VPN if you must proceed</span>
                                        </li>
                                        <li className="flex items-center space-x-2">
                                          <AlertTriangle className="h-5 w-5 text-red-400 flex-shrink-0" />
                                          <span>Report suspicious activity if you encounter any issues</span>
                                        </li>
                                      </ul>
                                    </div>
                                  </div>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                  <p className="text-sm text-gray-400 mt-3">
                    Free scans available. Sign up for unlimited scanning and advanced features.
                  </p>
                </CardContent>
              </Card>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-20">
              <div className="text-center">
                <div className="text-4xl font-bold text-blue-400 mb-2">
                  {loading ? (
                    <div className="animate-pulse">Loading...</div>
                  ) : (
                    formatNumber(analytics?.urlsScanned ?? 0)
                  )}
                </div>
                <div className="text-gray-300">Total URLs Scanned</div>
              </div>
              <div className="text-center">
                <div className="text-4xl font-bold text-red-400 mb-2">
                  {loading ? (
                    <div className="animate-pulse">Loading...</div>
                  ) : (
                    `${(analytics?.threatDetectionRate ?? 0).toFixed(1)}%`
                  )}
                </div>
                <div className="text-gray-300">Threat Detection Rate</div>
                <div className="text-sm text-gray-400 mt-1">
                  Real-time threat detection
                </div>
              </div>
              <div className="text-center">
                <div className="text-4xl font-bold text-cyan-400 mb-2">
                  {loading ? (
                    <div className="animate-pulse">Loading...</div>
                  ) : (
                    formatNumber(analytics?.protectedUsers ?? 0)
                  )}
                </div>
                <div className="text-gray-300">Protected Users</div>
              </div>
            </div>
          </div>
        </div>

        {/* Background Elements */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute -top-40 -right-40 w-80 h-80 bg-blue-500/20 rounded-full blur-3xl"></div>
          <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-cyan-500/20 rounded-full blur-3xl"></div>
        </div>
      </section>

      {/* Recent Scans Section */}
      {scanStats && scanStats.recentScans && (
        <section className="py-20 bg-black/20">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center mb-16">
              <h2 className="text-4xl font-bold text-white mb-4">Recent Activity</h2>
              <p className="text-xl text-gray-300 max-w-2xl mx-auto">
                Latest scans and threat statistics
              </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              {/* Recent Scans List */}
              <Card className="bg-white/5 backdrop-blur-sm border-white/10">
                <CardContent className="p-6">
                  <h3 className="text-2xl font-bold text-white mb-4">Latest Scans</h3>
                  <div className="space-y-4">
                    {loading ? (
                      <div className="animate-pulse space-y-4">
                        {[...Array(5)].map((_, index) => (
                          <div key={index} className="h-16 bg-white/5 rounded-lg"></div>
                        ))}
                      </div>
                    ) : scanStats.recentScans.length > 0 ? (
                      scanStats.recentScans.map((scan, index) => (
                        <div key={index} className="flex items-center justify-between p-4 bg-white/5 rounded-lg">
                          <div className="flex-1">
                            <p className="text-white truncate">{scan.url}</p>
                            <p className="text-sm text-gray-400">
                              {new Date(scan.scannedAt).toLocaleString()}
                            </p>
                          </div>
                          <div className="ml-4">
                            {scan.isSafe ? (
                              <CheckCircle className="w-6 h-6 text-green-400" />
                            ) : (
                              <AlertTriangle className="w-6 h-6 text-red-400" />
                            )}
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="text-center text-gray-400 py-4">
                        No recent scans available
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* Scan Statistics */}
              <Card className="bg-white/5 backdrop-blur-sm border-white/10">
                <CardContent className="p-6">
                  <h3 className="text-2xl font-bold text-white mb-4">Scan Statistics</h3>
                  <div className="space-y-6">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="p-4 bg-white/5 rounded-lg">
                        <p className="text-gray-400">Total Scans</p>
                        <p className="text-2xl font-bold text-white">
                          {loading ? (
                            <span className="inline-block animate-pulse h-8 w-16 bg-white/5 rounded"></span>
                          ) : (
                            scanStats.totalScans
                          )}
                        </p>
                      </div>
                      <div className="p-4 bg-white/5 rounded-lg">
                        <p className="text-gray-400">Safety Rate</p>
                        <p className="text-2xl font-bold text-white">
                          {loading ? (
                            <span className="inline-block animate-pulse h-8 w-16 bg-white/5 rounded"></span>
                          ) : (
                            `${scanStats?.safetyRate || '0.0'}%`
                          )}
                        </p>
                      </div>
                    </div>
                    
                    <div>
                      <h4 className="text-lg font-semibold text-white mb-3">Top Threats</h4>
                      <div className="space-y-2">
                        {loading ? (
                          <div className="animate-pulse space-y-2">
                            {[...Array(3)].map((_, index) => (
                              <div key={index} className="h-12 bg-white/5 rounded-lg"></div>
                            ))}
                          </div>
                        ) : scanStats.topThreats && scanStats.topThreats.length > 0 ? (
                          scanStats.topThreats.map((threat, index) => (
                            <div key={index} className="flex justify-between items-center p-3 bg-white/5 rounded-lg">
                              <span className="text-white">{threat._id}</span>
                              <span className="text-gray-400">{threat.count} occurrences</span>
                            </div>
                          ))
                        ) : (
                          <div className="text-center text-gray-400 py-2">
                            No threats detected
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </section>
      )}

      {/* Features Section */}
      <section className="py-20 bg-black/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-white mb-4">Advanced Protection Features</h2>
            <p className="text-xl text-gray-300 max-w-2xl mx-auto">
              Our cutting-edge technology provides comprehensive protection against online threats
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <Card className="bg-white/5 backdrop-blur-sm border-white/10 hover:bg-white/10 transition-all duration-300">
              <CardContent className="p-8 text-center">
                <div className="w-16 h-16 bg-gradient-to-r from-blue-500 to-cyan-500 rounded-full flex items-center justify-center mx-auto mb-6">
                  <AlertTriangle className="w-8 h-8 text-white" />
                </div>
                <h3 className="text-2xl font-bold text-white mb-4">Phishing Detection</h3>
                <p className="text-gray-300">
                  Advanced AI algorithms detect sophisticated phishing attempts and fraudulent websites
                </p>
              </CardContent>
            </Card>

            <Card className="bg-white/5 backdrop-blur-sm border-white/10 hover:bg-white/10 transition-all duration-300">
              <CardContent className="p-8 text-center">
                <div className="w-16 h-16 bg-gradient-to-r from-green-500 to-emerald-500 rounded-full flex items-center justify-center mx-auto mb-6">
                  <CheckCircle className="w-8 h-8 text-white" />
                </div>
                <h3 className="text-2xl font-bold text-white mb-4">Real-time Analysis</h3>
                <p className="text-gray-300">
                  Instant scanning results with comprehensive threat analysis and safety scores
                </p>
              </CardContent>
            </Card>

            <Card className="bg-white/5 backdrop-blur-sm border-white/10 hover:bg-white/10 transition-all duration-300">
              <CardContent className="p-8 text-center">
                <div className="w-16 h-16 bg-gradient-to-r from-purple-500 to-pink-500 rounded-full flex items-center justify-center mx-auto mb-6">
                  <Lock className="w-8 h-8 text-white" />
                </div>
                <h3 className="text-2xl font-bold text-white mb-4">Privacy First</h3>
                <p className="text-gray-300">We don&apos;t store or track your browsing history</p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20">
        <div className="max-w-4xl mx-auto text-center px-4 sm:px-6 lg:px-8">
          <h2 className="text-4xl font-bold text-white mb-6">Ready to Browse Safely?</h2>
          <p className="text-xl text-gray-300 mb-8">
            Join thousands of users who trust NetSafeScan to protect them online
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link href="/signup">
              <Button className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white px-8 py-3 text-lg">
                Get Started Free
              </Button>
            </Link>
            <Button variant="outline" className="border-white/20 text-white hover:bg-white/10 px-8 py-3 text-lg">
              Learn More
            </Button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-white/10 bg-black/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <div 
              className="flex items-center space-x-2 mb-4 md:mb-0 cursor-pointer hover:opacity-80 transition-opacity"
              onClick={handleLogoClick}
            >
              <Shield className="h-6 w-6 text-blue-400" />
              <span className="text-xl font-bold text-white">NetSafeScan</span>
            </div>
            <div className="flex flex-col items-center md:items-end space-y-2">
              <div className="text-gray-400 text-sm">© 2025 NetSafeScan. All rights reserved.</div>
              <div className="flex items-center space-x-1 text-gray-400 text-sm">
                <span>Made with</span>
                <svg className="w-4 h-4 text-red-400" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z" />
                </svg>
                <span>by</span>
                <span className="text-blue-400 font-medium">Kiel</span>
              </div>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
