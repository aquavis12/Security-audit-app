import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8080';

function App() {
  const [formData, setFormData] = useState({
    accountId: '',
    roleName: '',
    externalId: '',
    s3Bucket: ''
  });
  
  const [selectedRegions, setSelectedRegions] = useState([]);
  const [availableChecks, setAvailableChecks] = useState([]);
  const [selectedChecks, setSelectedChecks] = useState([]);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');
  
  const availableRegions = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
    'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
    'ap-south-1', 'ca-central-1', 'sa-east-1', 'me-south-1', 'af-south-1'
  ];

  useEffect(() => {
    fetchAvailableChecks();
  }, []);

  const fetchAvailableChecks = async () => {
    try {
      const response = await axios.get(`${API_URL}/api/checks`);
      setAvailableChecks(response.data.checks);
      setSelectedChecks(response.data.checks.map(c => c.id));
    } catch (err) {
      console.error('Failed to fetch checks:', err);
    }
  };

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleCheckToggle = (checkId) => {
    setSelectedChecks(prev =>
      prev.includes(checkId)
        ? prev.filter(id => id !== checkId)
        : [...prev, checkId]
    );
  };

  const handleSelectAll = () => {
    setSelectedChecks(availableChecks.map(c => c.id));
  };

  const handleDeselectAll = () => {
    setSelectedChecks([]);
  };

  const handleRegionChange = (e) => {
    const region = e.target.value;
    if (region && !selectedRegions.includes(region)) {
      if (selectedRegions.length < 3) {
        setSelectedRegions([...selectedRegions, region]);
      }
    }
  };

  const handleRemoveRegion = (region) => {
    setSelectedRegions(selectedRegions.filter(r => r !== region));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setResults(null);
    setLoading(true);

    try {
      if (selectedRegions.length === 0) {
        setError('Please select at least one region');
        setLoading(false);
        return;
      }

      const response = await axios.post(`${API_URL}/api/audit`, {
        accountId: formData.accountId,
        roleName: formData.roleName,
        externalId: formData.externalId,
        s3Bucket: formData.s3Bucket,
        regions: selectedRegions,
        selectedChecks
      });

      setResults(response.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Audit failed. Please check your credentials and try again.');
    } finally {
      setLoading(false);
    }
  };

  const downloadPDF = () => {
    if (results?.report?.presigned_url) {
      // Open S3 presigned URL in new tab
      window.open(results.report.presigned_url, '_blank');
    } else {
      alert('PDF report URL not available');
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'Critical': '#d32f2f',
      'High': '#f57c00',
      'Medium': '#fbc02d',
      'Low': '#388e3c'
    };
    return colors[severity] || '#666';
  };

  return (
    <div className="App">
      <div className="container">
        <header className="header">
          <h1>🛡️ AWS Security Audit Tool</h1>
          <p>Comprehensive security assessment for your AWS environment</p>
        </header>

        <div className="content">
          <form onSubmit={handleSubmit} className="audit-form">
            <div className="form-section">
              <h2>AWS Account Configuration</h2>
              
              <div className="form-group">
                <label>AWS Regions (Max 3) *</label>
                <div className="region-info">
                  <small style={{ color: '#1565C0', fontSize: '0.9rem', fontWeight: '500' }}>
                    💡 Tip: Auditing 1 region at a time is faster. Max 3 regions per audit.
                  </small>
                </div>
                
                <select
                  value=""
                  onChange={handleRegionChange}
                  disabled={selectedRegions.length >= 3}
                  className="region-dropdown"
                >
                  <option value="">
                    {selectedRegions.length >= 3 ? 'Max 3 regions selected' : 'Select a region...'}
                  </option>
                  {availableRegions
                    .filter(r => !selectedRegions.includes(r))
                    .map(region => (
                      <option key={region} value={region}>
                        {region}
                      </option>
                    ))}
                </select>

                {selectedRegions.length > 0 && (
                  <div className="selected-regions">
                    <label style={{ display: 'block', marginBottom: '8px', fontWeight: '500' }}>
                      Selected Regions ({selectedRegions.length}/3):
                    </label>
                    <div className="region-tags">
                      {selectedRegions.map(region => (
                        <div key={region} className="region-tag">
                          <span>{region}</span>
                          <button
                            type="button"
                            onClick={() => handleRemoveRegion(region)}
                            className="remove-region"
                            title="Remove region"
                          >
                            ✕
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              <div className="form-group">
                <label>AWS Account ID *</label>
                <input
                  type="text"
                  name="accountId"
                  value={formData.accountId}
                  onChange={handleInputChange}
                  placeholder="123456789012"
                  pattern="[0-9]{12}"
                  required
                />
              </div>

              <div className="form-group">
                <label>IAM Role Name *</label>
                <input
                  type="text"
                  name="roleName"
                  value={formData.roleName}
                  onChange={handleInputChange}
                  placeholder="SecurityAuditRole"
                  required
                />
              </div>

              <div className="form-group">
                <label>External ID *</label>
                <input
                  type="text"
                  name="externalId"
                  value={formData.externalId}
                  onChange={handleInputChange}
                  placeholder="Required for cross-account security"
                  required
                />
                <small style={{ color: '#666', fontSize: '0.85rem', marginTop: '5px', display: 'block' }}>
                  ⚠️ External ID is mandatory to prevent confused deputy attacks
                </small>
              </div>

              <div className="form-group">
                <label>S3 Bucket for Reports (Optional)</label>
                <input
                  type="text"
                  name="s3Bucket"
                  value={formData.s3Bucket}
                  onChange={handleInputChange}
                  placeholder="Leave empty for auto-generated bucket name"
                />
                <small style={{ color: '#666', fontSize: '0.85rem', marginTop: '5px', display: 'block' }}>
                  Default: aws-security-audit-{'{accountId}'}-{'{region}'}
                </small>
              </div>
            </div>

            <div className="form-section">
              <div className="checks-header">
                <h2>Security Checks</h2>
                <div className="check-actions">
                  <button type="button" onClick={handleSelectAll} className="btn-link">
                    Select All
                  </button>
                  <button type="button" onClick={handleDeselectAll} className="btn-link">
                    Deselect All
                  </button>
                </div>
              </div>

              <div className="checks-grid">
                {availableChecks.map(check => (
                  <label key={check.id} className="check-item">
                    <input
                      type="checkbox"
                      checked={selectedChecks.includes(check.id)}
                      onChange={() => handleCheckToggle(check.id)}
                    />
                    <div className="check-content">
                      <span className="check-name">{check.name}</span>
                      <span
                        className="check-severity"
                        style={{ color: getSeverityColor(check.severity) }}
                      >
                        {check.severity}
                      </span>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            {error && (
              <div className="error-message">
                ⚠️ {error}
              </div>
            )}

            <button
              type="submit"
              className="btn-primary"
              disabled={loading || selectedChecks.length === 0}
            >
              {loading ? 'Running Audit...' : 'Run Security Audit'}
            </button>
          </form>

          {results && (
            <div className="results">
              <div className="results-header">
                <h2>Audit Results</h2>
                <div className="results-actions">
                  <button onClick={downloadPDF} className="btn-secondary">
                    📄 Download PDF Report
                  </button>
                  {results.report && (
                    <div className="s3-info">
                      <small style={{ color: '#666' }}>
                        📦 Stored in S3: {results.report.s3_bucket}
                      </small>
                    </div>
                  )}
                </div>
              </div>

              <div className="summary-cards">
                <div className="summary-card critical">
                  <div className="card-value">{results.summary.critical}</div>
                  <div className="card-label">Critical</div>
                </div>
                <div className="summary-card high">
                  <div className="card-value">{results.summary.high}</div>
                  <div className="card-label">High</div>
                </div>
                <div className="summary-card medium">
                  <div className="card-value">{results.summary.medium}</div>
                  <div className="card-label">Medium</div>
                </div>
                <div className="summary-card low">
                  <div className="card-value">{results.summary.low}</div>
                  <div className="card-label">Low</div>
                </div>
              </div>

              <div className="findings-list">
                {results.findings.map((finding, index) => (
                  <div key={index} className="finding-item">
                    <div className="finding-header">
                      <h3>{finding.check.replace(/_/g, ' ')}</h3>
                      <span className="finding-count">{finding.count} issues</span>
                    </div>
                    <div className="finding-items">
                      {finding.items.slice(0, 5).map((item, idx) => (
                        <div key={idx} className="item">
                          {typeof item === 'string' ? item : JSON.stringify(item).substring(0, 100)}
                        </div>
                      ))}
                      {finding.count > 5 && (
                        <div className="item-more">
                          ... and {finding.count - 5} more
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <footer className="footer">
          <p>AWS Security Audit Tool | Powered by SUDO</p>
        </footer>
      </div>
    </div>
  );
}

export default App;
