import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Bar } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend } from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

const API_BASE = 'https://secora-backend.onrender.com/api';

export default function App() {
  const [dashboard, setDashboard] = useState(null);
  const [audit, setAudit] = useState([]);
  const [chainStatus, setChainStatus] = useState('');
  const [runId, setRunId] = useState(1); // Default for demo

  useEffect(() => {
    fetchDashboard();
    fetchAudit();
  }, [runId]);

  const fetchDashboard = async () => {
    try {
      const res = await axios.get(`${API_BASE}/dashboard/${runId}`);
      setDashboard(res.data);
    } catch (e) { console.error(e); }
  };

  const fetchAudit = async () => {
    try {
      const res = await axios.get(`${API_BASE}/blockchain`);
      setAudit(res.data);
      const verifyRes = await axios.get(`${API_BASE}/blockchain/verify`);
      setChainStatus(verifyRes.data.status);
    } catch (e) { console.error(e); }
  };

  const chartData = {
    labels: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    datasets: [{
      label: 'Risk Distribution',
      data: dashboard ? [
        dashboard.distribution.LOW, 
        dashboard.distribution.MEDIUM, 
        dashboard.distribution.HIGH, 
        dashboard.distribution.CRITICAL
      ] : [0,0,0,0],
      backgroundColor: ['#22c55e', '#eab308', '#f97316', '#ef4444'],
    }]
  };

  return (
    <div className="min-h-screen p-8">
      <header className="mb-8 flex justify-between items-center border-b pb-4">
        <h1 className="text-3xl font-bold text-gray-800">SECORA Dashboard</h1>
        <div className="flex gap-4 items-center">
          <span className="text-sm text-gray-500">Run ID: {runId}</span>
          <span className={`px-4 py-1 rounded font-bold text-white ${chainStatus === 'VALID' ? 'bg-green-600' : 'bg-red-600'}`}>
            Ledger: {chainStatus}
          </span>
        </div>
      </header>

      {dashboard?.status === 'stale' && (
        <div className="bg-yellow-100 text-yellow-800 p-4 rounded mb-6 font-semibold">
          Warning: Live models unavailable. Displaying previously committed stale evidence.
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
        <div className="bg-white p-6 rounded shadow border">
          <h2 className="text-xl font-semibold mb-4">Aggregate Risk Distribution</h2>
          <Bar data={chartData} />
        </div>

        <div className="bg-white p-6 rounded shadow border overflow-auto max-h-96">
          <h2 className="text-xl font-semibold mb-4">Flagged Entities (High/Critical)</h2>
          {dashboard?.flags?.map((flag, idx) => (
            <div key={idx} className="mb-4 border-b pb-4">
              <div className="flex justify-between items-center">
                <span className="font-bold">{flag.company}</span>
                <span className="text-sm bg-red-100 text-red-800 px-2 py-1 rounded">Risk: {flag.risk} / 100</span>
              </div>
              <div className="text-sm text-gray-600 mt-2">
                <strong>Z-Score Explanations: </strong><br/>
                Emissions Intensity: {flag.z_scores.emissions_intensity?.toFixed(2)} | 
                Cyber Incidents: {flag.z_scores.incidents?.toFixed(2)} | 
                Score Inconsistency: {flag.z_scores.score_consistency?.toFixed(2)}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-white p-6 rounded shadow border overflow-auto max-h-96">
        <h2 className="text-xl font-semibold mb-4">Cryptographic Audit Trail (Latest)</h2>
        <table className="w-full text-left text-sm text-gray-600">
          <thead className="bg-gray-100">
            <tr>
              <th className="p-2">Timestamp</th>
              <th className="p-2">Req ID</th>
              <th className="p-2">Tuple (R, sE, sC)</th>
              <th className="p-2">Current SHA-256</th>
            </tr>
          </thead>
          <tbody>
            {audit.map((block) => (
              <tr key={block.id} className="border-b">
                <td className="p-2">{new Date(block.timestamp).toLocaleString()}</td>
                <td className="p-2">{block.request_id.split('-')[0]}...</td>
                <td className="p-2">{`R:${block.payload.R}, sE:${block.payload.sE}, sC:${block.payload.sC}`}</td>
                <td className="p-2 font-mono text-xs text-gray-400">{block.curr_hash.substring(0, 32)}...</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
