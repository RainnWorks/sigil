/**
 * A real countdown driven by wall-clock time, not frame count. The numeric
 * readout re-renders about four times a second; the smooth gauge depletion is
 * animated separately in the gauge component off the render loop (Reanimated),
 * so a slow render never makes the clock lie.
 */
import { useEffect, useRef, useState } from "react";

export type Phase = "fresh" | "expiring" | "expired";

export interface Countdown {
  remainingMs: number;
  /** 1 at receipt, 0 at expiry. */
  fraction: number;
  phase: Phase;
}

/** `expiringThresholdMs`: when to flip to the "expiring" phase (default 10s). */
export function useCountdown(
  expiresAt: number,
  timeoutMs: number,
  expiringThresholdMs = 10_000,
): Countdown {
  const compute = (): Countdown => {
    const remainingMs = Math.max(0, expiresAt - Date.now());
    const fraction = timeoutMs > 0 ? Math.max(0, Math.min(1, remainingMs / timeoutMs)) : 0;
    const phase: Phase =
      remainingMs <= 0 ? "expired" : remainingMs <= expiringThresholdMs ? "expiring" : "fresh";
    return { remainingMs, fraction, phase };
  };

  const [value, setValue] = useState<Countdown>(compute);
  const raf = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    setValue(compute());
    raf.current = setInterval(() => {
      const next = compute();
      setValue(next);
      if (next.phase === "expired" && raf.current) {
        clearInterval(raf.current);
        raf.current = null;
      }
    }, 250);
    return () => {
      if (raf.current) clearInterval(raf.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [expiresAt, timeoutMs]);

  return value;
}
