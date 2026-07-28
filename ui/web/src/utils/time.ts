// Small date helpers for showing cache age. No dependency — plain Intl/Date.

/** Relative age like "3 minutes ago" / "just now" from an ISO timestamp. */
export function formatAge(iso?: string | null): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 5) return "just now";
  const units: [number, string][] = [
    [60, "second"],
    [60, "minute"],
    [24, "hour"],
    [30, "day"],
    [12, "month"],
    [Number.POSITIVE_INFINITY, "year"],
  ];
  let value = seconds;
  for (let i = 0; i < units.length; i++) {
    const [divisor, name] = units[i];
    if (value < divisor) {
      const v = Math.floor(value);
      return `${v} ${name}${v === 1 ? "" : "s"} ago`;
    }
    value = value / divisor;
  }
  return new Date(iso).toLocaleString();
}

/** Absolute, human-readable timestamp. */
export function formatAbsolute(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

/** Human-readable byte size. */
export function formatBytes(bytes: number): string {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i ? 1 : 0)} ${units[i]}`;
}
