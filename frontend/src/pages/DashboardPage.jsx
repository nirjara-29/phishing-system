import React, { useEffect, useState } from 'react';
import { getDashboardStats, getThreatTrend, getTopThreats, getRecentScans } from '../api/dashboard';
import StatsCards from '../components/Dashboard/StatsCards';
import ThreatTrend from '../components/Dashboard/ThreatTrend';
import TopThreats from '../components/Dashboard/TopThreats';
import RecentScans from '../components/Dashboard/RecentScans';
import Loading from '../components/Common/Loading';

export default function DashboardPage() {
  const [stats, setStats] = useState(null);
  const [trend, setTrend] = useState([]);
  const [topThreats, setTopThreats] = useState([]);
  const [recentScans, setRecentScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [s, t, tt, rs] = await Promise.allSettled([
          getDashboardStats(),
          getThreatTrend(7),
          getTopThreats(10),
          getRecentScans(15),
        ]);
        if (s.status === 'fulfilled') setStats(s.value);
        if (t.status === 'fulfilled') setTrend(t.value?.data || t.value || []);
        if (tt.status === 'fulfilled') setTopThreats(tt.value?.items || tt.value || []);
        if (rs.status === 'fulfilled') setRecentScans(rs.value?.items || rs.value || []);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) return <Loading text="Loading dashboard..." />;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-sm text-gray-500 mt-1">Overview of your phishing detection activity</p>
      </div>

      <StatsCards stats={stats} />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <ThreatTrend data={trend} />
        <TopThreats threats={topThreats} />
      </div>

      <RecentScans scans={recentScans} />
    </div>
  );
}
