import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [health, setHealth] = useState(null);
  const [events, setEvents] = useState([]);
  const [verification, setVerification] = useState(null);
  const [testResults, setTestResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Fetch health status
  const fetchHealth = async () => {
    try {
      const response = await axios.get('/health');
      setHealth(response.data);
    } catch (error) {
      console.error('Failed to fetch health:', error);
    }
  };

  // Fetch audit events
  const fetchEvents = async () => {
    try {
      const response = await axios.get('/events?limit=50');
      setEvents(response.data.events);
    } catch (error) {
      console.error('Failed to fetch events:', error);
    }
  };

  // Fetch test results from demo runner output
  const fetchTestResults = async () => {
    try {
      // In production, this would fetch from the broker or a results endpoint
      // For now, we'll simulate with local data or show a message
      const response = await axios.get('/demo_results.json').catch(() => null);
      if (response && response.data) {
        setTestResults(response.data);
      }
    } catch (error) {
      console.error('Failed to fetch test results:', error);
    }
  };

  // Verify audit log
  const verifyAuditLog = async () => {
    setVerifying(true);
    try {
      const response = await axios.get('/verify-log');
      setVerification(response.data);
    } catch (error) {
      console.error('Failed to verify audit log:', error);
    } finally {
      setVerifying(false);
    }
  };

  // Initial load
  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await Promise.all([
        fetchHealth(),
        fetchEvents(),
        fetchTestResults()
      ]);
      setLoading(false);
    };
    loadData();
  }, []);

  // Auto-refresh
  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      fetchHealth();
      fetchEvents();
    }, 5000); // Refresh every 5 seconds

    return () => clearInterval(interval);
  }, [autoRefresh]);

  // Calculate statistics
  const stats = events.reduce((acc, event) => {
    if (event.decision === 'allow') acc.allowed++;
    if (event.decision === 'deny') acc.denied++;
    return acc;
  }, { allowed: 0, denied: 0 });

  if (loading) {
    return (
      <div className="App">
        <div className="loading">Loading Glasshouse Dashboard...</div>
      </div>
    );
  }

  return (
    <div className="App">
      <header className="App-header">
        <h1>🏛️ Glasshouse Security Dashboard</h1>
        <p className="subtitle">AI Security Testing Environment</p>
        <label className="auto-refresh">
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => setAutoRefresh(e.target.checked)}
          />
          Auto-refresh
        </label>
      </header>

      <div className="dashboard">
        {/* Zone Status Section */}
        <section className="section zone-status">
          <h2>Zone Status</h2>
          <div className="zones">
            <ZoneCard name="Broker" status={health ? "operational" : "unknown"} color="#3498db" />
            <ZoneCard name="Red Zone" status="active" color="#e74c3c" />
            <ZoneCard name="Blue Zone" status="active" color="#2ecc71" />
            <ZoneCard
              name="Model Zone"
              status={health?.ollama_available ? "online" : "offline"}
              color="#9b59b6"
            />
          </div>
        </section>

        {/* System Health */}
        <section className="section system-health">
          <h2>System Health</h2>
          {health && (
            <div className="health-details">
              <HealthItem
                label="Broker Status"
                value={health.status}
                good={health.status === "healthy"}
              />
              <HealthItem
                label="Ollama Connection"
                value={health.ollama_available ? "Connected" : "Disconnected"}
                good={health.ollama_available}
              />
              <HealthItem
                label="Audit Log"
                value={health.audit_log_writable ? "Writable" : "Error"}
                good={health.audit_log_writable}
              />
              <HealthItem
                label="Last Check"
                value={new Date(health.timestamp).toLocaleTimeString()}
                good={true}
              />
            </div>
          )}
        </section>

        {/* Statistics */}
        <section className="section statistics">
          <h2>Request Statistics</h2>
          <div className="stats-grid">
            <StatCard label="Total Events" value={events.length} color="#3498db" />
            <StatCard label="Allowed" value={stats.allowed} color="#2ecc71" />
            <StatCard label="Denied" value={stats.denied} color="#e74c3c" />
            <StatCard
              label="Block Rate"
              value={events.length > 0 ? `${((stats.denied / events.length) * 100).toFixed(1)}%` : "0%"}
              color="#f39c12"
            />
          </div>
        </section>

        {/* Attack Test Scoreboard */}
        {testResults && (
          <section className="section test-results">
            <h2>Attack Test Results</h2>
            <div className="test-summary">
              <div className={`test-stat ${testResults.failed_tests === 0 ? 'pass' : 'fail'}`}>
                <span className="test-label">Pass Rate</span>
                <span className="test-value">
                  {testResults.total_tests > 0
                    ? `${((testResults.passed_tests / testResults.total_tests) * 100).toFixed(1)}%`
                    : "N/A"}
                </span>
              </div>
              <div className="test-stat pass">
                <span className="test-label">Passed</span>
                <span className="test-value">{testResults.passed_tests}</span>
              </div>
              <div className="test-stat fail">
                <span className="test-label">Failed</span>
                <span className="test-value">{testResults.failed_tests}</span>
              </div>
            </div>
            <div className="test-list">
              {testResults.results.map((test, idx) => (
                <TestResultItem key={idx} test={test} />
              ))}
            </div>
          </section>
        )}

        {/* Audit Log Verification */}
        <section className="section verification">
          <h2>Audit Log Integrity</h2>
          <button
            className="verify-button"
            onClick={verifyAuditLog}
            disabled={verifying}
          >
            {verifying ? "Verifying..." : "🔍 Verify Audit Log"}
          </button>
          {verification && (
            <div className={`verification-result ${verification.valid ? 'valid' : 'invalid'}`}>
              <div className="verification-status">
                {verification.valid ? "✓ VALID" : "✗ INVALID"}
              </div>
              <div className="verification-details">
                <p>Total entries: {verification.total_entries}</p>
                {!verification.valid && verification.first_invalid_entry && (
                  <p className="error">First invalid entry: #{verification.first_invalid_entry}</p>
                )}
                {!verification.valid && verification.error_message && (
                  <p className="error">{verification.error_message}</p>
                )}
                <p className="timestamp">
                  Verified at: {new Date(verification.verified_at).toLocaleString()}
                </p>
              </div>
            </div>
          )}
        </section>

        {/* Recent Events */}
        <section className="section events">
          <h2>Recent Activity</h2>
          <div className="events-list">
            {events.length === 0 ? (
              <p className="no-events">No events yet</p>
            ) : (
              events.slice(0, 20).map((event, idx) => (
                <EventItem key={idx} event={event} />
              ))
            )}
          </div>
        </section>
      </div>

      <footer className="App-footer">
        <p>Glasshouse v1.0.0 | Person 2: Policy Broker</p>
      </footer>
    </div>
  );
}

// Component: Zone Card
function ZoneCard({ name, status, color }) {
  const statusClass = status === "operational" || status === "online" || status === "active"
    ? "online"
    : "offline";

  return (
    <div className="zone-card" style={{ borderLeftColor: color }}>
      <div className="zone-name">{name}</div>
      <div className={`zone-status ${statusClass}`}>
        {status}
      </div>
    </div>
  );
}

// Component: Health Item
function HealthItem({ label, value, good }) {
  return (
    <div className="health-item">
      <span className="health-label">{label}:</span>
      <span className={`health-value ${good ? 'good' : 'bad'}`}>
        {good ? "✓" : "✗"} {value}
      </span>
    </div>
  );
}

// Component: Stat Card
function StatCard({ label, value, color }) {
  return (
    <div className="stat-card" style={{ borderTopColor: color }}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

// Component: Test Result Item
function TestResultItem({ test }) {
  return (
    <div className={`test-item ${test.passed ? 'test-pass' : 'test-fail'}`}>
      <div className="test-icon">{test.passed ? "✓" : "✗"}</div>
      <div className="test-details">
        <div className="test-name">{test.test_name}</div>
        <div className="test-category">{test.category}</div>
        <div className="test-outcome">{test.actual_outcome}</div>
      </div>
    </div>
  );
}

// Component: Event Item
function EventItem({ event }) {
  const decisionClass = event.decision === 'allow' ? 'allowed' : 'denied';
  const zoneColor = {
    red: '#e74c3c',
    blue: '#2ecc71',
    broker: '#3498db',
    model: '#9b59b6'
  }[event.zone] || '#95a5a6';

  return (
    <div className="event-item">
      <div className="event-time">
        {new Date(event.timestamp).toLocaleTimeString()}
      </div>
      <div className="event-zone" style={{ backgroundColor: zoneColor }}>
        {event.zone}
      </div>
      <div className="event-action">{event.action}</div>
      <div className={`event-decision ${decisionClass}`}>
        {event.decision}
      </div>
      <div className="event-reason">{event.reason}</div>
    </div>
  );
}

export default App;
