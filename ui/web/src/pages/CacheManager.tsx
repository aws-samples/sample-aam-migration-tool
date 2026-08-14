import { useEffect, useState } from "react";
import Alert from "@cloudscape-design/components/alert";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import Container from "@cloudscape-design/components/container";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import Modal from "@cloudscape-design/components/modal";
import SpaceBetween from "@cloudscape-design/components/space-between";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import Table from "@cloudscape-design/components/table";
import { api, type CacheEntry } from "../api/client";
import { exportToCsv } from "../utils/csv";
import { formatAbsolute, formatAge, formatBytes } from "../utils/time";

// Cache overview + clear. Lets the user see what's cached (age, size, summary)
// and decide what to clear. Cache files persist across server restarts; this
// is the only thing that removes them.
export default function CacheManager({ active }: { active: boolean }) {
  const [entries, setEntries] = useState<CacheEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  // Pending clear action (a specific key, or "ALL"); drives the confirm modal.
  const [confirm, setConfirm] = useState<{ key?: string; label: string } | null>(null);

  function refresh() {
    setLoading(true);
    api
      .cacheOverview()
      .then((r) => setEntries(r.entries))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }

  // The page stays mounted across tab switches, so refresh each time it becomes
  // visible to reflect cache changes from recent scans/discovery.
  useEffect(() => {
    if (active) refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  async function doClear() {
    if (!confirm) return;
    try {
      await api.cacheClear(confirm.key);
      setConfirm(null);
      refresh();
    } catch (e) {
      setError((e as Error).message);
      setConfirm(null);
    }
  }

  const anyCached = entries.some((e) => e.exists);

  function handleExport() {
    if (!entries.length) return;
    exportToCsv("cache_overview.csv", entries.map((e) => ({
      label: e.label,
      status: e.exists ? "Cached" : "Empty",
      summary: e.summary,
      age: formatAge(e.cached_at),
      size: formatBytes(e.size_bytes),
    })), [
      { key: "label", header: "Cache" },
      { key: "status", header: "Status" },
      { key: "summary", header: "Contents" },
      { key: "age", header: "Age" },
      { key: "size", header: "Size" },
    ]);
  }

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Local cache of scan results and discovery dumps. These files persist across restarts and are re-read on load. Clearing forces fresh data on the next run."
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button iconName="download" onClick={handleExport} disabled={!entries.length}>
                Export CSV
              </Button>
              <Button iconName="refresh" onClick={refresh}>
                Refresh
              </Button>
              <Button
                variant="primary"
                disabled={!anyCached}
                onClick={() => setConfirm({ label: "all cached data" })}
              >
                Clear all
              </Button>
            </SpaceBetween>
          }
        >
          Cache
        </Header>
      }
    >
      <SpaceBetween size="l">
        {error && (
          <Alert type="error" header="Cache error" dismissible onDismiss={() => setError(null)}>
            {error}
          </Alert>
        )}

        <Container>
          <Table
            variant="embedded"
            resizableColumns
            loading={loading}
            items={entries}
            trackBy="key"
            empty={<Box textAlign="center">No cache files.</Box>}
            columnDefinitions={[
              { id: "label", header: "Cache", cell: (e) => e.label, minWidth: 150 },
              {
                id: "status",
                header: "Status",
                minWidth: 100,
                cell: (e) =>
                  e.exists ? (
                    <StatusIndicator type="success">Cached</StatusIndicator>
                  ) : (
                    <StatusIndicator type="stopped">Empty</StatusIndicator>
                  ),
              },
              { id: "summary", header: "Contents", cell: (e) => e.summary, minWidth: 150 },
              {
                id: "age",
                header: "Age",
                minWidth: 100,
                cell: (e) => (
                  <span title={formatAbsolute(e.cached_at)}>{formatAge(e.cached_at)}</span>
                ),
              },
              { id: "size", header: "Size", cell: (e) => formatBytes(e.size_bytes), minWidth: 80 },
              {
                id: "actions",
                header: "",
                minWidth: 80,
                cell: (e) => (
                  <Button
                    variant="inline-link"
                    disabled={!e.exists}
                    onClick={() => setConfirm({ key: e.key, label: e.label })}
                  >
                    Clear
                  </Button>
                ),
              },
            ]}
          />
        </Container>
      </SpaceBetween>

      <Modal
        visible={!!confirm}
        header="Clear cache"
        onDismiss={() => setConfirm(null)}
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setConfirm(null)}>
                Cancel
              </Button>
              <Button variant="primary" onClick={doClear}>
                Clear
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        Clear <b>{confirm?.label}</b>? This deletes the local cache file. The next run will
        fetch fresh data from AWS.
      </Modal>
    </ContentLayout>
  );
}
