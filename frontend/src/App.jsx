import React, { useEffect, useState } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Info, 
  ExternalLink, 
  SlidersHorizontal, 
  Layers, 
  Search, 
  RefreshCw, 
  GitBranch, 
  Check, 
  Database, 
  Clock,
  ArrowRight,
  AlertCircle
} from 'lucide-react';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

function App() {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [stats, setStats] = useState({ total: 0, critical: 0, high: 0, medium: 0, low: 0 });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  
  // Selection and Interaction states
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [remediation, setRemediation] = useState(null);
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [feedbackForm, setFeedbackForm] = useState({ platform: 'github', issue_url: '', remediation_advice: '' });
  const [submittingFeedback, setSubmittingFeedback] = useState(false);
  const [feedbackSuccess, setFeedbackSuccess] = useState(false);

  // Filters
  const [severityFilter, setSeverityFilter] = useState('');
  const [projectFilter, setProjectFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  const fetchData = async (showRefreshIndicator = false) => {
    if (showRefreshIndicator) setRefreshing(true);
    else setLoading(true);
    
    try {
      const [vulnRes, statsRes] = await Promise.all([
        fetch(`${API_URL}/dashboard/vulnerabilities/`),
        fetch(`${API_URL}/dashboard/stats/`)
      ]);
      
      if (!vulnRes.ok || !statsRes.ok) {
        throw new Error(`Failed to fetch dashboard data`);
      }
      
      const vulnData = await vulnRes.json();
      const statsData = await statsRes.json();
      
      setVulnerabilities(vulnData.vulnerabilities || []);
      setStats(statsData);
      setError(null);
    } catch (error) {
      console.error(error);
      setError(error);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRemediation = async (vuln) => {
    setRemediationLoading(true);
    setRemediation(null);
    try {
      const res = await fetch(`${API_URL}/remediation/?severity=${vuln.severity}&vuln_type=${vuln.type}`);
      if (!res.ok) throw new Error();
      const data = await res.json();
      setRemediation(data);
    } catch (err) {
      setRemediation({ advice: "Review OWASP security guidelines for remediation practices corresponding to " + vuln.type + "." });
    } finally {
      setRemediationLoading(false);
    }
  };

  // Run remediation fetch whenever selectedVuln changes
  useEffect(() => {
    if (selectedVuln) {
      handleRemediation(selectedVuln);
      setFeedbackForm({
        platform: 'github',
        issue_url: '',
        remediation_advice: ''
      });
      setFeedbackSuccess(false);
    }
  }, [selectedVuln]);

  const handleFeedbackSubmit = async (e) => {
    e.preventDefault();
    if (!selectedVuln) return;
    
    setSubmittingFeedback(true);
    setFeedbackSuccess(false);
    try {
      const res = await fetch(`${API_URL}/feedback/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vulnerability_id: selectedVuln.id,
          ...feedbackForm
        })
      });
      if (!res.ok) throw new Error();
      setFeedbackSuccess(true);
      setTimeout(() => setFeedbackSuccess(false), 5000);
      setFeedbackForm({ platform: 'github', issue_url: '', remediation_advice: '' });
    } catch (err) {
      alert('Failed to submit feedback. Please check backend connection.');
    } finally {
      setSubmittingFeedback(false);
    }
  };

  // Get unique projects for filter dropdown
  const projects = [...new Set(vulnerabilities.map(v => v.project))].filter(Boolean);

  // Filter vulnerabilities locally for high-speed interactions
  const filteredVulnerabilities = vulnerabilities.filter(vuln => {
    const matchesSeverity = !severityFilter || vuln.severity === severityFilter;
    const matchesProject = !projectFilter || vuln.project === projectFilter;
    
    const query = searchQuery.toLowerCase().trim();
    const matchesSearch = !query || 
      vuln.type.toLowerCase().includes(query) ||
      vuln.description.toLowerCase().includes(query) ||
      vuln.scanner.toLowerCase().includes(query) ||
      vuln.project.toLowerCase().includes(query) ||
      vuln.branch.toLowerCase().includes(query);

    return matchesSeverity && matchesProject && matchesSearch;
  });

  const getSeverityStyles = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return { color: 'var(--severity-critical)', badgeClass: 'badge-critical' };
      case 'HIGH':
        return { color: 'var(--severity-high)', badgeClass: 'badge-high' };
      case 'MEDIUM':
        return { color: 'var(--severity-medium)', badgeClass: 'badge-medium' };
      case 'LOW':
        return { color: 'var(--severity-low)', badgeClass: 'badge-low' };
      default:
        return { color: 'var(--text-muted)', badgeClass: '' };
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return <ShieldAlert className="w-5 h-5" style={{ color: 'var(--severity-critical)' }} />;
      case 'HIGH':
        return <AlertTriangle className="w-5 h-5" style={{ color: 'var(--severity-high)' }} />;
      case 'MEDIUM':
        return <Info className="w-5 h-5" style={{ color: 'var(--severity-medium)' }} />;
      case 'LOW':
        return <ShieldCheck className="w-5 h-5" style={{ color: 'var(--severity-low)' }} />;
      default:
        return <Info className="w-5 h-5" />;
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Navigation Header */}
      <header style={{
        borderBottom: '1px solid var(--border-color)',
        padding: '1rem 2rem',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        background: 'rgba(10, 15, 29, 0.6)',
        backdropFilter: 'blur(12px)',
        position: 'sticky',
        top: 0,
        zIndex: 50
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{
            background: 'linear-gradient(135deg, var(--accent-primary), var(--accent-secondary))',
            width: '40px',
            height: '40px',
            borderRadius: '10px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 15px rgba(99, 102, 241, 0.4)'
          }}>
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 style={{ fontSize: '1.25rem', fontWeight: 700, margin: 0, background: 'linear-gradient(to right, #ffffff, #d1d5db)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              SecOps Orchestrator
            </h1>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', margin: 0 }}>
              Automated Vulnerability Management Console
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem' }}>
            <span style={{
              width: '8px',
              height: '8px',
              backgroundColor: 'var(--severity-low)',
              borderRadius: '50%',
              boxShadow: '0 0 10px var(--severity-low)',
              display: 'inline-block'
            }}></span>
            <span style={{ color: 'var(--text-secondary)' }}>System Active</span>
          </div>

          <button 
            onClick={() => fetchData(true)} 
            disabled={refreshing}
            className="btn btn-secondary"
            style={{ padding: '0.5rem 0.75rem', fontSize: '0.8rem', minWidth: '100px' }}
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            {refreshing ? 'Syncing...' : 'Sync'}
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main style={{ flex: 1, padding: '2rem', maxWidth: '1600px', width: '100%', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        
        {/* Connection Error Message */}
        {error && (
          <div style={{
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.2)',
            borderRadius: '10px',
            padding: '1rem 1.5rem',
            display: 'flex',
            alignItems: 'center',
            gap: '1rem',
            color: 'var(--severity-critical)'
          }}>
            <AlertCircle className="w-6 h-6 flex-shrink-0" />
            <div>
              <h4 style={{ margin: 0, fontWeight: 600 }}>Backend Connection Error</h4>
              <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                Unable to contact the orchestration backend. Check if the container is running. Fallback values will be used.
              </p>
            </div>
            <button onClick={() => fetchData()} className="btn btn-primary" style={{ marginLeft: 'auto', padding: '0.5rem 1rem', fontSize: '0.8rem' }}>
              Retry
            </button>
          </div>
        )}

        {/* Stats Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1.25rem' }}>
          <div 
            onClick={() => setSeverityFilter('')}
            className={`stats-card total ${!severityFilter ? 'glass-panel' : ''}`}
            style={{ cursor: 'pointer', transition: 'all 0.2s ease' }}
          >
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontWeight: 500 }}>TOTAL FINDINGS</span>
            <span style={{ fontSize: '2.25rem', fontWeight: 800, color: '#ffffff' }}>{stats.total}</span>
          </div>

          <div 
            onClick={() => setSeverityFilter('CRITICAL')}
            className={`stats-card critical ${severityFilter === 'CRITICAL' ? 'glass-panel' : ''}`}
            style={{ cursor: 'pointer', transition: 'all 0.2s ease' }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontWeight: 500 }}>CRITICAL</span>
              <ShieldAlert className="w-4 h-4 text-red-500" style={{ color: 'var(--severity-critical)' }} />
            </div>
            <span style={{ fontSize: '2.25rem', fontWeight: 800, color: 'var(--severity-critical)' }}>{stats.critical}</span>
          </div>

          <div 
            onClick={() => setSeverityFilter('HIGH')}
            className={`stats-card high ${severityFilter === 'HIGH' ? 'glass-panel' : ''}`}
            style={{ cursor: 'pointer', transition: 'all 0.2s ease' }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontWeight: 500 }}>HIGH</span>
              <AlertTriangle className="w-4 h-4" style={{ color: 'var(--severity-high)' }} />
            </div>
            <span style={{ fontSize: '2.25rem', fontWeight: 800, color: 'var(--severity-high)' }}>{stats.high}</span>
          </div>

          <div 
            onClick={() => setSeverityFilter('MEDIUM')}
            className={`stats-card medium ${severityFilter === 'MEDIUM' ? 'glass-panel' : ''}`}
            style={{ cursor: 'pointer', transition: 'all 0.2s ease' }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontWeight: 500 }}>MEDIUM</span>
              <Info className="w-4 h-4" style={{ color: 'var(--severity-medium)' }} />
            </div>
            <span style={{ fontSize: '2.25rem', fontWeight: 800, color: 'var(--severity-medium)' }}>{stats.medium}</span>
          </div>

          <div 
            onClick={() => setSeverityFilter('LOW')}
            className={`stats-card low ${severityFilter === 'LOW' ? 'glass-panel' : ''}`}
            style={{ cursor: 'pointer', transition: 'all 0.2s ease' }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontWeight: 500 }}>LOW</span>
              <ShieldCheck className="w-4 h-4" style={{ color: 'var(--severity-low)' }} />
            </div>
            <span style={{ fontSize: '2.25rem', fontWeight: 800, color: 'var(--severity-low)' }}>{stats.low}</span>
          </div>
        </div>

        {/* Dashboard Workspace */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 420px', gap: '2rem', alignItems: 'start', flex: 1 }}>
          
          {/* Left Column: Filter and List */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            
            {/* Filter Bar */}
            <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-secondary)' }}>
                <SlidersHorizontal className="w-4 h-4" />
                <span style={{ fontSize: '0.85rem', fontWeight: 500 }}>Filters</span>
              </div>

              {/* Search */}
              <div style={{ position: 'relative', flex: 1, minWidth: '200px' }}>
                <Search className="w-4 h-4" style={{ position: 'absolute', left: '0.9rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input 
                  type="text" 
                  placeholder="Search vulnerabilities, projects, scanners..." 
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="input-control"
                  style={{ paddingLeft: '2.5rem' }}
                />
              </div>

              {/* Severity Dropdown */}
              <select 
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="input-control"
                style={{ width: 'auto', minWidth: '150px' }}
              >
                <option value="">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>

              {/* Project Dropdown */}
              <select 
                value={projectFilter}
                onChange={(e) => setProjectFilter(e.target.value)}
                className="input-control"
                style={{ width: 'auto', minWidth: '150px' }}
              >
                <option value="">All Projects</option>
                {projects.map(project => (
                  <option key={project} value={project}>{project}</option>
                ))}
              </select>
            </div>

            {/* Vulnerabilities List */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {loading ? (
                <div style={{ padding: '4rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
                  <RefreshCw className="w-8 h-8 animate-spin" style={{ margin: '0 auto 1rem auto', color: 'var(--accent-primary)' }} />
                  <p>Loading security findings...</p>
                </div>
              ) : filteredVulnerabilities.length === 0 ? (
                <div className="glass-panel" style={{ padding: '4rem 2rem', textAlign: 'center' }}>
                  <ShieldCheck className="w-16 h-16" style={{ margin: '0 auto 1.5rem auto', color: 'var(--severity-low)', filter: 'drop-shadow(0 0 15px rgba(16, 185, 129, 0.2))' }} />
                  <h3 style={{ fontSize: '1.25rem', fontWeight: 600, marginBottom: '0.5rem' }}>No Vulnerabilities Found</h3>
                  <p style={{ color: 'var(--text-secondary)', maxWidth: '400px', margin: '0 auto', fontSize: '0.9rem' }}>
                    Your system check passed! No security vulnerabilities match the selected filter criteria.
                  </p>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: 'var(--text-muted)', padding: '0 0.5rem' }}>
                    <span>SHOWING {filteredVulnerabilities.length} OF {vulnerabilities.length} FINDINGS</span>
                  </div>
                  {filteredVulnerabilities.map((vuln) => {
                    const styles = getSeverityStyles(vuln.severity);
                    const isSelected = selectedVuln?.id === vuln.id;
                    return (
                      <div 
                        key={vuln.id}
                        onClick={() => setSelectedVuln(vuln)}
                        className={`glass-panel vuln-item animate-fade-in ${vuln.severity.toLowerCase()} ${isSelected ? 'selected' : ''}`}
                        style={{
                          padding: '1.25rem',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '0.85rem'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                              <span className={`badge ${styles.badgeClass}`}>{vuln.severity}</span>
                              <span className="badge badge-scanner">{vuln.scanner}</span>
                              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                                <Clock className="w-3.5 h-3.5" />
                                {new Date(vuln.created_at).toLocaleDateString()}
                              </span>
                            </div>
                            <h3 style={{ fontSize: '1.05rem', color: '#ffffff', fontWeight: 600 }}>{vuln.type}</h3>
                          </div>
                          <ArrowRight className={`w-5 h-5 ${isSelected ? 'text-indigo-400' : 'text-gray-600'} transition-transform`} style={{ transform: isSelected ? 'translateX(3px)' : 'none', color: isSelected ? 'var(--accent-primary)' : 'var(--text-muted)' }} />
                        </div>

                        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.5, display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                          {vuln.description}
                        </p>

                        <div style={{ display: 'flex', gap: '1rem', borderTop: '1px solid rgba(255,255,255,0.03)', paddingTop: '0.75rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                            <Layers className="w-3.5 h-3.5 text-indigo-400" style={{ color: 'var(--accent-secondary)' }} />
                            <span>Project: <strong>{vuln.project}</strong></span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                            <GitBranch className="w-3.5 h-3.5 text-emerald-400" style={{ color: 'var(--severity-low)' }} />
                            <span>Branch: <strong>{vuln.branch}</strong></span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

          </div>

          {/* Right Column: Orchestration and Remediation Details Panel */}
          <div className="glass-panel animate-fade-in" style={{ padding: '1.5rem', position: 'sticky', top: '80px', minHeight: '400px', display: 'flex', flexDirection: 'column' }}>
            {!selectedVuln ? (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center', padding: '2rem 1rem', color: 'var(--text-muted)' }}>
                <Shield className="w-16 h-16" style={{ color: 'rgba(255, 255, 255, 0.05)', marginBottom: '1.25rem', filter: 'drop-shadow(0 0 10px rgba(99, 102, 241, 0.05))' }} />
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>Select Finding</h3>
                <p style={{ fontSize: '0.85rem', lineHeight: 1.4 }}>
                  Select a vulnerability from the dashboard to investigate details, fetch remediation guides, and orchestrate tickets.
                </p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                
                {/* Header Information */}
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      {getSeverityIcon(selectedVuln.severity)}
                      <span style={{ fontSize: '0.75rem', fontWeight: 700, color: getSeverityStyles(selectedVuln.severity).color }}>
                        {selectedVuln.severity}
                      </span>
                    </div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      ID: #{selectedVuln.id}
                    </span>
                  </div>
                  <h2 style={{ fontSize: '1.25rem', color: '#ffffff', fontWeight: 700, lineHeight: 1.3, marginBottom: '0.75rem' }}>
                    {selectedVuln.type}
                  </h2>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', background: 'rgba(0,0,0,0.2)', padding: '0.75rem', borderRadius: '8px', fontSize: '0.75rem' }}>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Scanner:</span>
                      <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.1rem' }}>{selectedVuln.scanner}</p>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Project:</span>
                      <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.1rem' }}>{selectedVuln.project}</p>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Branch:</span>
                      <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.1rem', wordBreak: 'break-all' }}>{selectedVuln.branch}</p>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Detected:</span>
                      <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.1rem' }}>{new Date(selectedVuln.created_at).toLocaleDateString()}</p>
                    </div>
                  </div>
                </div>

                {/* Description */}
                <div>
                  <h4 style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.35rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Description</h4>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5, background: 'rgba(255,255,255,0.01)', padding: '0.75rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.02)' }}>
                    {selectedVuln.description}
                  </p>
                </div>

                {/* Remediation Guide */}
                <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '1.25rem' }}>
                  <h4 style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.5rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <Info className="w-4 h-4 text-indigo-400" style={{ color: 'var(--accent-primary)' }} />
                    Remediation Advice
                  </h4>
                  {remediationLoading ? (
                    <div style={{ padding: '1rem 0', display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                      <RefreshCw className="w-4 h-4 animate-spin text-indigo-400" />
                      <span>Loading remediation guide...</span>
                    </div>
                  ) : remediation ? (
                    <div style={{
                      background: 'rgba(99, 102, 241, 0.04)',
                      border: '1px solid rgba(99, 102, 241, 0.12)',
                      borderRadius: '8px',
                      padding: '0.85rem 1rem',
                      fontSize: '0.85rem',
                      lineHeight: 1.4,
                      color: '#e0e7ff'
                    }}>
                      {remediation.advice}
                    </div>
                  ) : (
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No remediation guide loaded.</p>
                  )}
                </div>

                {/* Ticket/Feedback Orchestration */}
                <form onSubmit={handleFeedbackSubmit} style={{ borderTop: '1px solid var(--border-color)', paddingTop: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                  <h4 style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <Database className="w-4 h-4" style={{ color: 'var(--accent-secondary)' }} />
                    Orchestrate Ticket
                  </h4>
                  
                  {feedbackSuccess && (
                    <div style={{
                      background: 'rgba(16, 185, 129, 0.1)',
                      border: '1px solid rgba(16, 185, 129, 0.2)',
                      borderRadius: '8px',
                      padding: '0.75rem',
                      fontSize: '0.8rem',
                      color: 'var(--severity-low)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem'
                    }}>
                      <Check className="w-4 h-4" />
                      Ticket and feedback logged successfully!
                    </div>
                  )}

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                    <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Target Platform</label>
                    <select 
                      value={feedbackForm.platform} 
                      onChange={(e) => setFeedbackForm({...feedbackForm, platform: e.target.value})}
                      className="input-control"
                    >
                      <option value="github">GitHub Issues</option>
                      <option value="jira">Jira Dashboard</option>
                    </select>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                    <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Issue/Ticket URL</label>
                    <input 
                      type="url" 
                      required
                      placeholder="https://github.com/org/repo/issues/1" 
                      value={feedbackForm.issue_url} 
                      onChange={(e) => setFeedbackForm({...feedbackForm, issue_url: e.target.value})}
                      className="input-control"
                    />
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                    <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Orchestration Notes</label>
                    <textarea 
                      placeholder="Assigning to engineering lead, scheduling patching cycle..." 
                      value={feedbackForm.remediation_advice} 
                      onChange={(e) => setFeedbackForm({...feedbackForm, remediation_advice: e.target.value})}
                      className="input-control"
                      style={{ height: '70px', resize: 'none' }}
                    />
                  </div>

                  <button 
                    type="submit" 
                    disabled={submittingFeedback}
                    className="btn btn-primary" 
                    style={{ width: '100%', marginTop: '0.25rem' }}
                  >
                    {submittingFeedback ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        Orchestrating...
                      </>
                    ) : (
                      <>
                        <ExternalLink className="w-4 h-4" />
                        Submit & Sync Ticket
                      </>
                    )}
                  </button>
                </form>

              </div>
            )}
          </div>

        </div>

      </main>
      
      {/* Footer */}
      <footer style={{
        textAlign: 'center',
        padding: '1.5rem',
        color: 'var(--text-muted)',
        fontSize: '0.75rem',
        borderTop: '1px solid var(--border-color)',
        marginTop: 'auto',
        background: 'rgba(10, 15, 29, 0.3)'
      }}>
        SecOps Orchestrator Console &copy; {new Date().getFullYear()} CityTech. All security intelligence data is encrypted in transit and at rest.
      </footer>
    </div>
  );
}

export default App;
