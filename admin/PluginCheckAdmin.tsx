import { useRef, useState, type ChangeEvent, type DragEvent } from 'react';
import type { RwpAdminPageProps } from '../../../src/lib/plugin-api';
import type { Finding, Names, Report } from '../lib/types';
import { checkPlugin } from '../lib/check';
import { reportForAi, verdictText } from '../lib/report';
import { unpackPluginZip, ZipProblem } from '../lib/zip';
import { loadSyntaxChecker } from '../lib/syntax';
import styles from './PluginCheck.module.css';

const MAX_ZIP_BYTES = 60 * 1024 * 1024;

const label: Record<Finding['severity'], string> = { error: 'Must fix', warning: 'Check', info: 'Note' };

function FindingRow({ finding }: { finding: Finding }) {
  return (
    <li className={`${styles.finding} ${styles[finding.severity]}`}>
      <div className={styles.findingHead}>
        <span className={styles.badge}>{label[finding.severity]}</span>
        {finding.file ? <code className={styles.where}>{finding.file}{finding.line ? `:${finding.line}` : ''}</code> : null}
      </div>
      <p className={styles.message}>{finding.message}</p>
      {finding.fix ? <p className={styles.fix}><strong>What to do:</strong> {finding.fix}</p> : null}
    </li>
  );
}

export default function PluginCheckAdmin(_props: RwpAdminPageProps) {
  const [running, setRunning] = useState(false);
  const [fileName, setFileName] = useState('');
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [dragging, setDragging] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  const run = async (file: File) => {
    setError('');
    setReport(null);
    setCopied(false);
    setFileName(file.name);
    if (!/\.zip$/i.test(file.name)) {
      setError('Choose the plugin\'s .zip file.');
      return;
    }
    if (file.size > MAX_ZIP_BYTES) {
      setError('This ZIP is larger than 60 MB. A plugin that size cannot be uploaded to the site either.');
      return;
    }
    setRunning(true);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const entries = unpackPluginZip(bytes);
      const [namesModule, syntax] = await Promise.all([import('../data/names.json'), loadSyntaxChecker()]);
      const names = (namesModule as unknown as { default: Names }).default;
      setReport(checkPlugin(entries, { names, syntax: syntax ?? undefined }));
    } catch (problem) {
      setError(problem instanceof ZipProblem ? problem.message : `The check could not run: ${(problem as Error)?.message || problem}`);
    } finally {
      setRunning(false);
    }
  };

  const onChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) void run(file);
    event.target.value = '';
  };
  const onDrop = (event: DragEvent) => {
    event.preventDefault();
    setDragging(false);
    const file = event.dataTransfer.files?.[0];
    if (file) void run(file);
  };

  const copy = async () => {
    if (!report) return;
    try {
      await navigator.clipboard.writeText(reportForAi(report));
      setCopied(true);
    } catch {
      setError('Copying was blocked by the browser. Select the problems below and copy them by hand.');
    }
  };

  const errors = report?.findings.filter((f) => f.severity === 'error') ?? [];
  const warnings = report?.findings.filter((f) => f.severity === 'warning') ?? [];
  const notes = report?.findings.filter((f) => f.severity === 'info') ?? [];

  return (
    <div className={styles.page}>
      <h1 className={styles.title}>Plugin Check</h1>
      <p className={styles.lead}>
        Test a plugin ZIP before you install it. Nothing is uploaded or installed: the file is read in this browser and
        you get a plain-language report. Use it on plugins made by the AI converter, or any plugin you did not write.
      </p>

      <div
        className={`${styles.drop} ${dragging ? styles.dropActive : ''}`}
        onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        <p>Drop the plugin .zip here, or</p>
        <button type="button" className={styles.primary} onClick={() => input.current?.click()} disabled={running}>
          {running ? 'Checking…' : 'Choose a ZIP file'}
        </button>
        <input ref={input} type="file" accept=".zip,application/zip" onChange={onChange} className={styles.hidden} aria-label="Plugin ZIP file" />
        {fileName ? <p className={styles.file}>{fileName}</p> : null}
      </div>

      {error ? <div className={styles.errorBox} role="alert">{error}</div> : null}

      {report ? (
        <section aria-live="polite">
          <div className={`${styles.verdict} ${styles[`verdict_${report.verdict}`]}`}>
            <h2>{report.plugin.name || report.plugin.id || 'Plugin'}{report.plugin.version ? ` ${report.plugin.version}` : ''}</h2>
            <p className={styles.verdictText}>{verdictText(report)}</p>
            <p className={styles.counts}>
              {report.counts.error} must fix · {report.counts.warning} to check · {report.files} files read
            </p>
            {report.counts.error + report.counts.warning > 0 ? (
              <div className={styles.actions}>
                <button type="button" className={styles.primary} onClick={() => void copy()}>
                  {copied ? 'Copied — paste it into the AI Factory' : 'Copy the report for the AI'}
                </button>
                <span className={styles.hint}>Paste it into the converter and ask it to return a fixed ZIP, then check again.</span>
              </div>
            ) : null}
          </div>

          {errors.length ? (
            <>
              <h3>Must fix ({errors.length})</h3>
              <ul className={styles.list}>{errors.map((f, i) => <FindingRow key={`e${i}`} finding={f} />)}</ul>
            </>
          ) : null}
          {warnings.length ? (
            <>
              <h3>Check these ({warnings.length})</h3>
              <ul className={styles.list}>{warnings.map((f, i) => <FindingRow key={`w${i}`} finding={f} />)}</ul>
            </>
          ) : null}
          {notes.length ? (
            <>
              <h3>Notes</h3>
              <ul className={styles.list}>{notes.map((f, i) => <FindingRow key={`n${i}`} finding={f} />)}</ul>
            </>
          ) : null}

          <details className={styles.scope}>
            <summary>What this check did and did not do</summary>
            <ul>{report.scope.map((line) => <li key={line}>{line}</li>)}</ul>
          </details>
        </section>
      ) : null}
    </div>
  );
}
