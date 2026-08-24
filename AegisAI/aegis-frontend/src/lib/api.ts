/**
 * api.ts — ALL fetch calls live here.
 * Handles transport, timeout, and error normalisation.
 */

import type { ScanResult } from '../types';
import { BASE_URL, ENDPOINTS } from './api.config';

// Valid risk levels — mirrors backend and types.ts
const VALID_RISK_LEVELS = new Set([
  'safe',
  'low',
  'medium',
  'high',
  'critical',
]);

// Local Ollama + Flask analysis can take longer than a normal API call.
// 5 minutes gives Granite enough time to finish.
const SCAN_TIMEOUT_MS = 5 * 60 * 1000;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function buildUrl(path: string): string {
  return `${BASE_URL}${path}`;
}

async function parseError(
  res: Response,
  fallback: string
): Promise<string> {
  try {
    const data = await res.json();
    return data.error ?? data.message ?? fallback;
  } catch {
    return fallback;
  }
}

/**
 * Creates an AbortController with an auto-abort timeout.
 */
function withTimeout(
  ms: number
): {
  ctrl: AbortController;
  cancel: () => void;
} {
  const ctrl = new AbortController();

  const timer = setTimeout(() => {
    ctrl.abort();
  }, ms);

  const cancel = () => {
    clearTimeout(timer);
  };

  return {
    ctrl,
    cancel,
  };
}

/**
 * Validate the parsed JSON response.
 */
function validateScanResult(data: unknown): ScanResult {
  if (!data || typeof data !== 'object') {
    throw new Error(
      'The scanner returned an unexpected response. Please try again.'
    );
  }

  const d = data as Record<string, unknown>;

  const risk =
    typeof d.risk_level === 'string'
      ? d.risk_level.toLowerCase()
      : '';

  if (!VALID_RISK_LEVELS.has(risk)) {
    throw new Error(
      `The scanner returned an unrecognised risk level ("${risk}"). Please try again.`
    );
  }

  if (
    !d.explanation ||
    typeof d.explanation !== 'string'
  ) {
    throw new Error(
      'The scanner returned an incomplete result. Please try again.'
    );
  }

  return d as unknown as ScanResult;
}

// ─── File Scan ───────────────────────────────────────────────────────────────

/**
 * Send an image / PDF file for scanning.
 */
export async function scanFile(
  file: File
): Promise<ScanResult> {

  // IMPORTANT:
  // Use 5 minutes instead of the old ~30 second timeout.
  const { ctrl, cancel } =
    withTimeout(SCAN_TIMEOUT_MS);

  const form = new FormData();

  form.append('file', file);

  let res: Response;

  try {
    res = await fetch(
      buildUrl(ENDPOINTS.scan),
      {
        method: 'POST',
        body: form,
        signal: ctrl.signal,
      }
    );
  } catch (err) {

    cancel();

    if (
      (err as Error).name === 'AbortError'
    ) {
      throw new Error(
        'Scan timed out after 5 minutes. Please make sure Ollama and the backend are running.'
      );
    }

    throw new Error(
      'Could not reach the scanner. Make sure the backend is running.'
    );
  }

  // Fetch finished successfully.
  cancel();

  if (!res.ok) {

    const msg = await parseError(
      res,
      `Server error ${res.status}`
    );

    throw new Error(msg);
  }

  let data: unknown;

  try {
    data = await res.json();
  } catch {
    throw new Error(
      'The scanner returned an invalid response.'
    );
  }

  return validateScanResult(data);
}

// ─── URL / Text Scan ─────────────────────────────────────────────────────────

/**
 * Send a URL or pasted text for scanning.
 */
export async function scanText(
  input: string,
  mode: 'url' | 'text' = 'url'
): Promise<ScanResult> {

  const { ctrl, cancel } =
    withTimeout(SCAN_TIMEOUT_MS);

  const body =
    mode === 'url'
      ? { url: input }
      : { text: input };

  let res: Response;

  try {

    res = await fetch(
      buildUrl(ENDPOINTS.scanUrl),
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
        signal: ctrl.signal,
      }
    );

  } catch (err) {

    cancel();

    if (
      (err as Error).name === 'AbortError'
    ) {
      throw new Error(
        'Scan timed out after 5 minutes. Please make sure Ollama and the backend are running.'
      );
    }

    throw new Error(
      'Could not reach the scanner. Make sure the backend is running.'
    );
  }

  cancel();

  if (!res.ok) {

    if (res.status === 404) {
      throw new Error(
        'URL/text scanning is not available right now.'
      );
    }

    const msg = await parseError(
      res,
      `Server error ${res.status}`
    );

    throw new Error(msg);
  }

  let data: unknown;

  try {
    data = await res.json();
  } catch {
    throw new Error(
      'The scanner returned an invalid response.'
    );
  }

  return validateScanResult(data);
}