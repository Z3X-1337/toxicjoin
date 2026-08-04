import { useCallback, useMemo, useState } from "react";

import { CONSOLE_PRESETS, DEFAULT_PRESET_ID, presetById } from "../data/presets";
import type { ConsolePreset } from "../data/presets";
import { ConsoleApiError, submitConsoleQuery } from "../lib/console";
import type { ConsoleMode } from "../lib/console";
import type { PipelineRequest, PipelineResponse } from "../types";

export interface ConsoleFormState {
  taskPurpose: string;
  sql: string;
  subjectDataset: string;
  subjectField: string;
  mode: ConsoleMode;
}

export interface ConsoleController extends ConsoleFormState {
  presets: readonly ConsolePreset[];
  activePresetId: string | null;
  running: boolean;
  result: PipelineResponse | null;
  error: string | null;
  errorCode: string | null;
  canSubmit: boolean;
  setTaskPurpose: (value: string) => void;
  setSql: (value: string) => void;
  setSubjectDataset: (value: string) => void;
  setSubjectField: (value: string) => void;
  setMode: (value: ConsoleMode) => void;
  applyPreset: (presetId: string) => void;
  submit: () => Promise<void>;
  reset: () => void;
}

function formFromPreset(preset: ConsolePreset): ConsoleFormState {
  return {
    taskPurpose: preset.request.task_purpose,
    sql: preset.request.sql,
    subjectDataset: preset.request.subject_key.dataset,
    subjectField: preset.request.subject_key.field_path,
    mode: preset.defaultMode,
  };
}

export function buildConsoleRequest(form: ConsoleFormState): PipelineRequest {
  return {
    task_purpose: form.taskPurpose.trim(),
    sql: form.sql.trim(),
    subject_key: {
      dataset: form.subjectDataset.trim(),
      field_path: form.subjectField.trim(),
    },
    dialect: "duckdb",
  };
}

export function isConsoleFormComplete(form: ConsoleFormState): boolean {
  return (
    form.taskPurpose.trim().length > 0 &&
    form.sql.trim().length > 0 &&
    form.subjectDataset.trim().length > 0 &&
    form.subjectField.trim().length > 0
  );
}

export function useQueryConsole(): ConsoleController {
  const initial = useMemo(() => formFromPreset(presetById(DEFAULT_PRESET_ID)), []);
  const [form, setForm] = useState<ConsoleFormState>(initial);
  const [activePresetId, setActivePresetId] = useState<string | null>(DEFAULT_PRESET_ID);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<PipelineResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);

  // Any manual edit detaches the form from its preset so the UI never claims a preset
  // produced a result the operator actually typed.
  const update = useCallback((patch: Partial<ConsoleFormState>, keepPreset = false) => {
    setForm((current) => ({ ...current, ...patch }));
    if (!keepPreset) {
      setActivePresetId(null);
    }
  }, []);

  const applyPreset = useCallback((presetId: string) => {
    const preset = presetById(presetId);
    setForm(formFromPreset(preset));
    setActivePresetId(preset.id);
    setResult(null);
    setError(null);
    setErrorCode(null);
  }, []);

  const submit = useCallback(async () => {
    if (!isConsoleFormComplete(form) || running) {
      return;
    }
    setRunning(true);
    setError(null);
    setErrorCode(null);
    try {
      const response = await submitConsoleQuery(buildConsoleRequest(form), form.mode);
      setResult(response);
    } catch (caught) {
      setResult(null);
      if (caught instanceof ConsoleApiError) {
        setError(caught.message);
        setErrorCode(caught.code ?? null);
      } else {
        setError("An unexpected error prevented the request.");
      }
    } finally {
      setRunning(false);
    }
  }, [form, running]);

  const reset = useCallback(() => {
    applyPreset(DEFAULT_PRESET_ID);
  }, [applyPreset]);

  return {
    ...form,
    presets: CONSOLE_PRESETS,
    activePresetId,
    running,
    result,
    error,
    errorCode,
    canSubmit: isConsoleFormComplete(form) && !running,
    setTaskPurpose: (value) => update({ taskPurpose: value }),
    setSql: (value) => update({ sql: value }),
    setSubjectDataset: (value) => update({ subjectDataset: value }),
    setSubjectField: (value) => update({ subjectField: value }),
    setMode: (value) => update({ mode: value }, true),
    applyPreset,
    submit,
    reset,
  };
}
