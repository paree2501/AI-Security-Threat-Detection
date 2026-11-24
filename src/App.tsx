import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar, TabId } from './components/Sidebar';
import { Header } from './components/Header';
import { OverviewTab } from './components/OverviewTab';
import { EventsTab } from './components/EventsTab';
import { DetectionsTab } from './components/DetectionsTab';
import { AIAssistantTab } from './components/AIAssistantTab';
import { IncidentsTab } from './components/IncidentsTab';
import { ReportsTab } from './components/ReportsTab';
import { SettingsTab } from './components/SettingsTab';
import { UploadModal } from './components/UploadModal';
import { IncidentDetailModal } from './components/IncidentDetailModal';
import {
  SecurityEvent,
  Detection,
  Incident,
  DetectionConfig,
  MLEvaluation,
  SystemStatus,
  SeverityLevel,
  IncidentStatus,
} from './types';
import {
  fetchEvents,
  fetchDetections,
  fetchIncidents,
  fetchSettings,
  fetchSystemStatus,
  fetchMLEvaluation,
  loadSampleEvents,
  clearAllEvents,
  runDetections,
  createIncident,
  updateIncident,
  trainMLModel,
  updateSettings,
  resetSettings,
} from './services/api';

export default function App() {
  const [currentTab, setCurrentTab] = useState<TabId>('overview');
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [config, setConfig] = useState<DetectionConfig | null>(null);
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [mlEvaluation, setMlEvaluation] = useState<MLEvaluation | null>(null);

  const [selectedDetectionIdForAI, setSelectedDetectionIdForAI] = useState<string>('');
  const [activeIncidentForModal, setActiveIncidentForModal] = useState<Incident | null>(null);
  const [isUploadModalOpen, setIsUploadModalOpen] = useState<boolean>(false);

  const [isReloading, setIsReloading] = useState<boolean>(false);
  const [isRerunning, setIsRerunning] = useState<boolean>(false);
  const [isRetrainingML, setIsRetrainingML] = useState<boolean>(false);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'info' | 'error' } | null>(null);

  const showToast = useCallback((message: string, type: 'success' | 'info' | 'error' = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  }, []);

  const loadAllData = useCallback(async () => {
    try {
      const [eventsRes, detRes, incRes, cfgRes, statusRes, mlRes] = await Promise.all([
        fetchEvents({ limit: 1000 }),
        fetchDetections(),
        fetchIncidents(),
        fetchSettings(),
        fetchSystemStatus(),
        fetchMLEvaluation(),
      ]);

      setEvents(eventsRes.events);
      setDetections(detRes.detections);
      setIncidents(incRes.incidents);
      setConfig(cfgRes);
      setStatus(statusRes);
      setMlEvaluation(mlRes.evaluation);

      if (detRes.detections.length > 0 && !selectedDetectionIdForAI) {
        setSelectedDetectionIdForAI(detRes.detections[0].detection_id);
      }
    } catch (err) {
      console.error('Failed to load application data:', err);
    }
  }, [selectedDetectionIdForAI]);

  useEffect(() => {
    loadAllData();
  }, [loadAllData]);

  const handleReloadSample = async () => {
    setIsReloading(true);
    try {
      await loadSampleEvents();
      await loadAllData();
    } catch (err) {
      console.error('Failed to reload sample dataset:', err);
    } finally {
      setIsReloading(false);
    }
  };

  const handleClearEvents = async () => {
    try {
      await clearAllEvents();
      setEvents([]);
      setDetections([]);
      setIncidents([]);
      await loadAllData();
    } catch (err) {
      console.error('Failed to clear events:', err);
    }
  };

  const handleRerunDetections = async () => {
    setIsRerunning(true);
    try {
      const res = await runDetections();
      setDetections(res.detections);
      const statusRes = await fetchSystemStatus();
      setStatus(statusRes);
    } catch (err) {
      console.error('Failed to rerun detections:', err);
    } finally {
      setIsRerunning(false);
    }
  };

  const handleRetrainML = async () => {
    setIsRetrainingML(true);
    try {
      const res = await trainMLModel();
      setMlEvaluation(res.evaluation);
      const statusRes = await fetchSystemStatus();
      setStatus(statusRes);
    } catch (err) {
      console.error('Failed to retrain ML model:', err);
    } finally {
      setIsRetrainingML(false);
    }
  };

  const handleCreateIncidentFromDetection = async (detection: Detection) => {
    try {
      const res = await createIncident({
        title: `Investigation: ${detection.rule_name}`,
        summary: detection.reason,
        related_detection_id: detection.detection_id,
        severity: detection.severity,
        analyst: 'Security Analyst',
      });
      setIncidents(prev => [res.incident, ...prev]);
      setActiveIncidentForModal(res.incident);
    } catch (err) {
      console.error('Failed to create incident from detection:', err);
    }
  };

  const handleCreateManualIncident = async (title: string, summary: string, severity: SeverityLevel) => {
    try {
      const res = await createIncident({
        title,
        summary,
        severity,
        analyst: 'Security Analyst',
      });
      setIncidents(prev => [res.incident, ...prev]);
      setActiveIncidentForModal(res.incident);
    } catch (err) {
      console.error('Failed to create manual incident:', err);
    }
  };

  const handleUpdateIncident = async (
    id: string,
    updates: {
      status?: IncidentStatus;
      severity?: SeverityLevel;
      newNote?: string;
      analyst?: string;
    }
  ) => {
    try {
      const res = await updateIncident(id, updates);
      setIncidents(prev => prev.map(i => (i.incident_id === id ? res.incident : i)));
      setActiveIncidentForModal(res.incident);
    } catch (err) {
      console.error('Failed to update incident:', err);
    }
  };

  const handleUpdateConfig = async (newCfg: Partial<DetectionConfig>) => {
    try {
      const updated = await updateSettings(newCfg);
      setConfig(updated);
      await loadAllData();
    } catch (err) {
      console.error('Failed to update settings:', err);
    }
  };

  const handleResetConfig = async () => {
    try {
      const reset = await resetSettings();
      setConfig(reset);
      await loadAllData();
    } catch (err) {
      console.error('Failed to reset settings:', err);
    }
  };

  const highAlertsCount = detections.filter(d => d.severity === 'HIGH' || d.severity === 'CRITICAL').length;
  const openIncidentsCount = incidents.filter(i => i.status === 'OPEN' || i.status === 'INVESTIGATING').length;

  return (
    <div className="flex h-screen bg-[#070d18] text-slate-100 overflow-hidden font-sans">
      {/* Sidebar */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        status={status}
        detectionsCount={detections.length}
        openIncidentsCount={openIncidentsCount}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Header */}
        <Header
          currentTab={currentTab}
          onOpenUpload={() => setIsUploadModalOpen(true)}
          onReloadSample={handleReloadSample}
          isReloading={isReloading}
          totalEvents={events.length}
          totalDetections={detections.length}
          highAlertsCount={highAlertsCount}
        />

        {/* Scrollable Tab Container */}
        <main className="flex-1 overflow-y-auto bg-gradient-to-b from-[#080e1a] via-[#091122] to-[#070d18]">
          {currentTab === 'overview' && (
            <OverviewTab
              events={events}
              detections={detections}
              incidents={incidents}
              onSelectTab={setCurrentTab}
              onSelectDetectionForAI={id => {
                setSelectedDetectionIdForAI(id);
                setCurrentTab('assistant');
              }}
              onOpenIncidentDetail={inc => setActiveIncidentForModal(inc)}
              onLoadSample={handleReloadSample}
            />
          )}

          {currentTab === 'events' && (
            <EventsTab
              events={events}
              onOpenUpload={() => setIsUploadModalOpen(true)}
              onReloadSample={handleReloadSample}
              onClearEvents={handleClearEvents}
              isReloading={isReloading}
            />
          )}

          {currentTab === 'detections' && (
            <DetectionsTab
              detections={detections}
              onRerunDetections={handleRerunDetections}
              onSelectForAI={id => {
                setSelectedDetectionIdForAI(id);
                setCurrentTab('assistant');
              }}
              onCreateIncidentFromDetection={handleCreateIncidentFromDetection}
              isRerunning={isRerunning}
            />
          )}

          {currentTab === 'assistant' && (
            <AIAssistantTab
              detections={detections}
              selectedDetectionId={selectedDetectionIdForAI}
              onSelectDetectionId={setSelectedDetectionIdForAI}
            />
          )}

          {currentTab === 'incidents' && (
            <IncidentsTab
              incidents={incidents}
              onOpenIncidentDetail={inc => setActiveIncidentForModal(inc)}
              onCreateManualIncident={handleCreateManualIncident}
            />
          )}

          {currentTab === 'reports' && (
            <ReportsTab
              events={events}
              detections={detections}
              incidents={incidents}
              mlEvaluation={mlEvaluation}
            />
          )}

          {currentTab === 'settings' && config && (
            <SettingsTab
              config={config}
              onUpdateConfig={handleUpdateConfig}
              onResetConfig={handleResetConfig}
              status={status}
              onRetrainML={handleRetrainML}
              isRetrainingML={isRetrainingML}
            />
          )}
        </main>
      </div>

      {/* Upload Modal */}
      <UploadModal
        isOpen={isUploadModalOpen}
        onClose={() => setIsUploadModalOpen(false)}
        onUploadSuccess={res => {
          loadAllData();
          showToast(`Successfully ingested ${res.added} events (${res.duplicates} duplicates skipped).`, 'success');
        }}
      />

      {/* Incident Detail Modal */}
      <IncidentDetailModal
        incident={activeIncidentForModal}
        isOpen={Boolean(activeIncidentForModal)}
        onClose={() => setActiveIncidentForModal(null)}
        onUpdate={handleUpdateIncident}
      />

      {/* In-App Toast Notification */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center space-x-2.5 px-4 py-3 rounded-xl bg-slate-900 border border-cyan-500/50 shadow-2xl shadow-cyan-950/50 text-xs font-medium text-slate-100 animate-in fade-in slide-in-from-bottom-3 duration-200">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          <span>{toast.message}</span>
          <button
            onClick={() => setToast(null)}
            className="ml-2 text-slate-400 hover:text-slate-200"
          >
            ✕
          </button>
        </div>
      )}
    </div>
  );
}
