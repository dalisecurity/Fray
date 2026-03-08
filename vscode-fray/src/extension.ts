import * as vscode from 'vscode';
import * as cp from 'child_process';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface FrayFinding {
  payload: string;
  status: number;
  blocked: boolean;
  reflected: boolean;
  bypass_confidence: number;
  fp_score: number;
  fp_reasons: string[];
  confidence_label: string;
  elapsed_ms: number;
  response_length?: number;
  error?: string;
}

interface FrayScanResult {
  target: string;
  summary?: {
    total_tested: number;
    blocked: number;
    passed: number;
    reflected: number;
    block_rate: string;
  };
  test_results?: FrayFinding[];
  duration?: string;
  auto_throttle?: Record<string, unknown>;
}

interface FrayHistoryEntry {
  command: string;
  target: string;
  timestamp: string;
  resultCount: number;
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

let outputChannel: vscode.OutputChannel;
let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let resultsProvider: FrayResultsProvider;
let historyProvider: FrayHistoryProvider;
let activeProcess: cp.ChildProcess | null = null;
let lastResults: { command: string; target: string; data: any } | null = null;

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------

export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel('Fray Security');
  diagnosticCollection = vscode.languages.createDiagnosticCollection('fray');

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left, 100
  );
  statusBarItem.command = 'fray.quickPick';
  statusBarItem.text = '$(shield) Fray';
  statusBarItem.tooltip = 'Fray Security Scanner';
  statusBarItem.show();

  // Tree views
  resultsProvider = new FrayResultsProvider();
  historyProvider = new FrayHistoryProvider(context);
  vscode.window.registerTreeDataProvider('fray.resultsView', resultsProvider);
  vscode.window.registerTreeDataProvider('fray.historyView', historyProvider);

  // Register commands
  context.subscriptions.push(
    outputChannel,
    diagnosticCollection,
    statusBarItem,
    vscode.commands.registerCommand('fray.scanUrl', () => promptAndRun('scan', context)),
    vscode.commands.registerCommand('fray.testUrl', () => promptAndRun('test', context)),
    vscode.commands.registerCommand('fray.reconUrl', () => promptAndRun('recon', context)),
    vscode.commands.registerCommand('fray.osintDomain', () => promptAndRun('osint', context)),
    vscode.commands.registerCommand('fray.leakSearch', () => promptAndRun('leak', context)),
    vscode.commands.registerCommand('fray.bypassUrl', () => promptAndRun('bypass', context)),
    vscode.commands.registerCommand('fray.detectWaf', () => promptAndRun('detect', context)),
    vscode.commands.registerCommand('fray.hardenUrl', () => promptAndRun('harden', context)),
    vscode.commands.registerCommand('fray.scanFromSelection', () => runFromSelection('scan', context)),
    vscode.commands.registerCommand('fray.quickPick', () => showQuickPick(context)),
    vscode.commands.registerCommand('fray.showReport', () => showReportWebview(context)),
    vscode.commands.registerCommand('fray.stopScan', () => stopRunning()),
  );

  // Check fray installation on activation
  checkFrayInstalled();
}

export function deactivate() {
  stopRunning();
}

// ---------------------------------------------------------------------------
// Quick Pick (command palette)
// ---------------------------------------------------------------------------

async function showQuickPick(context: vscode.ExtensionContext) {
  const items: vscode.QuickPickItem[] = [
    { label: '$(shield) Scan URL', description: 'Crawl + param discovery + payload injection', detail: 'fray scan' },
    { label: '$(beaker) Test URL', description: 'Test payloads against a specific URL', detail: 'fray test' },
    { label: '$(zap) WAF Bypass', description: '5-phase WAF evasion scorer with mutation loop', detail: 'fray bypass' },
    { label: '$(eye) Detect WAF', description: 'Fingerprint WAF vendor (25 vendors)', detail: 'fray detect' },
    { label: '$(verified) Harden Check', description: 'Security headers A-F grade + OWASP Top 10', detail: 'fray harden' },
    { label: '$(search) Recon URL', description: 'Reconnaissance: tech, headers, DNS, certs', detail: 'fray recon' },
    { label: '$(globe) OSINT Domain', description: 'OSINT: whois, emails, GitHub, typosquatting', detail: 'fray osint' },
    { label: '$(key) Leak Search', description: 'Search leaked credentials (GitHub + HIBP)', detail: 'fray leak' },
    { label: '$(open-preview) Show Last Report', description: 'Open HTML report of last scan results' },
    { label: '$(debug-stop) Stop Running Scan', description: 'Kill the currently running fray process' },
  ];

  const pick = await vscode.window.showQuickPick(items, {
    placeHolder: 'Select a Fray command to run...',
  });

  if (!pick) { return; }

  if (pick.label.includes('Stop')) {
    stopRunning();
    return;
  }

  if (pick.label.includes('Report')) {
    showReportWebview(context);
    return;
  }

  const cmd = pick.detail?.replace('fray ', '') || 'scan';
  await promptAndRun(cmd, context);
}

// ---------------------------------------------------------------------------
// URL extraction helpers
// ---------------------------------------------------------------------------

function extractUrlFromEditor(): string | undefined {
  const editor = vscode.window.activeTextEditor;
  if (!editor) { return undefined; }

  // Try selection first
  const selection = editor.selection;
  if (!selection.isEmpty) {
    const text = editor.document.getText(selection).trim();
    if (looksLikeUrl(text) || looksLikeDomain(text)) {
      return text;
    }
  }

  // Try current line
  const line = editor.document.lineAt(selection.active.line).text.trim();
  const urlMatch = line.match(/https?:\/\/[^\s"'<>]+/);
  if (urlMatch) { return urlMatch[0]; }

  const domainMatch = line.match(/\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/);
  if (domainMatch) { return domainMatch[0]; }

  return undefined;
}

function looksLikeUrl(s: string): boolean {
  return /^https?:\/\/.+/.test(s);
}

function looksLikeDomain(s: string): boolean {
  return /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(s);
}

// ---------------------------------------------------------------------------
// Prompt and run
// ---------------------------------------------------------------------------

async function promptAndRun(command: string, context: vscode.ExtensionContext) {
  const suggested = extractUrlFromEditor() || '';

  const placeholder = command === 'osint'
    ? 'Enter domain, email, or company name (e.g. example.com)'
    : command === 'leak'
    ? 'Enter domain or email (e.g. example.com, user@example.com)'
    : command === 'bypass'
    ? 'Enter target URL for WAF bypass assessment (e.g. https://example.com)'
    : command === 'detect'
    ? 'Enter target URL to detect WAF (e.g. https://example.com)'
    : command === 'harden'
    ? 'Enter target URL for hardening check (e.g. https://example.com)'
    : 'Enter target URL (e.g. https://example.com)';

  const target = await vscode.window.showInputBox({
    prompt: `Fray ${command}: ${placeholder}`,
    value: suggested,
    placeHolder: placeholder,
    validateInput: (value: string) => {
      if (!value.trim()) { return 'Target is required'; }
      return null;
    },
  });

  if (!target) { return; }

  await runFray(command, target.trim(), context);
}

async function runFromSelection(command: string, context: vscode.ExtensionContext) {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('No active editor');
    return;
  }

  const selection = editor.document.getText(editor.selection).trim();
  if (!selection) {
    vscode.window.showWarningMessage('No text selected');
    return;
  }

  await runFray(command, selection, context);
}

// ---------------------------------------------------------------------------
// Core: run fray
// ---------------------------------------------------------------------------

async function runFray(command: string, target: string, context: vscode.ExtensionContext) {
  if (activeProcess) {
    const choice = await vscode.window.showWarningMessage(
      'A Fray scan is already running. Stop it?',
      'Stop & Run New', 'Cancel'
    );
    if (choice !== 'Stop & Run New') { return; }
    stopRunning();
  }

  const config = vscode.workspace.getConfiguration('fray');
  const pythonPath = config.get<string>('pythonPath', 'python');

  // Build args
  const args = buildArgs(command, target, config);

  outputChannel.clear();
  outputChannel.show(true);
  outputChannel.appendLine(`━━━ Fray ${command.toUpperCase()} ━━━`);
  outputChannel.appendLine(`Target: ${target}`);
  outputChannel.appendLine(`Command: ${pythonPath} -m fray ${args.join(' ')}`);
  outputChannel.appendLine('');

  // Update status bar
  statusBarItem.text = '$(loading~spin) Fray: Running...';
  statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');

  diagnosticCollection.clear();

  const startTime = Date.now();
  let jsonBuffer = '';

  return new Promise<void>((resolve) => {
    activeProcess = cp.spawn(pythonPath, ['-m', 'fray', ...args], {
      cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || process.cwd(),
      env: { ...process.env },
    });

    activeProcess.stdout?.on('data', (data: { toString(): string }) => {
      const text = data.toString();
      outputChannel.append(text);
      jsonBuffer += text;
    });

    activeProcess.stderr?.on('data', (data: { toString(): string }) => {
      const text = data.toString();
      outputChannel.append(text);
    });

    activeProcess.on('close', (code: number | null) => {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      activeProcess = null;

      outputChannel.appendLine('');
      outputChannel.appendLine(`━━━ Completed in ${elapsed}s (exit code: ${code}) ━━━`);

      // Reset status bar
      statusBarItem.text = '$(shield) Fray';
      statusBarItem.backgroundColor = undefined;

      // Parse JSON results
      const results = tryParseJson(jsonBuffer);
      if (results) {
        processResults(command, target, results, context);
      }

      // Add to history
      historyProvider.addEntry({
        command,
        target,
        timestamp: new Date().toISOString(),
        resultCount: results?.test_results?.length || results?.results?.length || 0,
      }, context);

      if (code === 0) {
        vscode.window.showInformationMessage(
          `Fray ${command} completed for ${target}`,
          'Show Output'
        ).then((choice: string | undefined) => {
          if (choice === 'Show Output') { outputChannel.show(); }
        });
      } else {
        vscode.window.showErrorMessage(
          `Fray ${command} failed (exit code: ${code}). Check output panel.`
        );
      }

      resolve();
    });

    activeProcess.on('error', (err: NodeJS.ErrnoException) => {
      activeProcess = null;
      statusBarItem.text = '$(shield) Fray';
      statusBarItem.backgroundColor = undefined;
      outputChannel.appendLine(`Error: ${err.message}`);

      if (err.message.includes('ENOENT')) {
        vscode.window.showErrorMessage(
          `Could not find "${pythonPath}". Set fray.pythonPath in settings.`,
          'Open Settings'
        ).then((choice: string | undefined) => {
          if (choice === 'Open Settings') {
            vscode.commands.executeCommand('workbench.action.openSettings', 'fray.pythonPath');
          }
        });
      }

      resolve();
    });
  });
}

// ---------------------------------------------------------------------------
// Build CLI args
// ---------------------------------------------------------------------------

function buildArgs(command: string, target: string, config: vscode.WorkspaceConfiguration): string[] {
  const args = [command, target, '--json'];

  if (command === 'scan' || command === 'test' || command === 'bypass') {
    const category = config.get<string>('defaultCategory', 'xss');
    const maxPayloads = config.get<number>('maxPayloads', 5);
    const timeout = config.get<number>('timeout', 8);
    const delay = config.get<number>('delay', 0.5);

    if (command !== 'bypass') {
      args.push('-c', category, '-m', String(maxPayloads));
    } else {
      args.push('-c', category);
    }
    args.push('-t', String(timeout), '-d', String(delay));

    if (config.get<boolean>('autoThrottle', false)) {
      args.push('--auto-throttle');
    }
    if (config.get<boolean>('stealth', false)) {
      args.push('--stealth');
    }
    if (command === 'scan' && config.get<boolean>('browserMode', false)) {
      args.push('--browser');
    }
  }

  if (command === 'detect' || command === 'harden') {
    const timeout = config.get<number>('timeout', 8);
    args.push('-t', String(timeout));
  }

  if (command === 'recon' || command === 'osint' || command === 'leak') {
    const timeout = config.get<number>('timeout', 8);
    args.push('-t', String(timeout));
  }

  const webhook = config.get<string>('notifyWebhook', '');
  if (webhook && (command === 'scan' || command === 'osint' || command === 'leak' || command === 'cred')) {
    args.push('--notify', webhook);
  }

  return args;
}

// ---------------------------------------------------------------------------
// Process results → diagnostics + tree view
// ---------------------------------------------------------------------------

function processResults(command: string, target: string, results: any, context: vscode.ExtensionContext) {
  lastResults = { command, target, data: results };
  const findings: FrayFinding[] = results.test_results || results.results || [];

  // Update tree view
  resultsProvider.setResults(command, target, findings, results);

  // Create diagnostics for bypasses
  if (!vscode.workspace.getConfiguration('fray').get<boolean>('showInlineFindings', true)) {
    return;
  }

  const editor = vscode.window.activeTextEditor;
  if (!editor) { return; }

  const diagnostics: vscode.Diagnostic[] = [];

  // Find the URL in the current document to anchor diagnostics
  const doc = editor.document;
  const docText = doc.getText();

  // Try to find the target URL in the document
  let anchorRange: vscode.Range | null = null;
  const targetIdx = docText.indexOf(target);
  if (targetIdx >= 0) {
    const startPos = doc.positionAt(targetIdx);
    const endPos = doc.positionAt(targetIdx + target.length);
    anchorRange = new vscode.Range(startPos, endPos);
  }

  // If we can't find the URL, use line 0
  if (!anchorRange) {
    anchorRange = new vscode.Range(0, 0, 0, Math.min(doc.lineAt(0).text.length, 80));
  }

  for (const finding of findings) {
    if (finding.blocked) { continue; }

    const severity = finding.fp_score > 50
      ? vscode.DiagnosticSeverity.Information
      : finding.bypass_confidence >= 70
      ? vscode.DiagnosticSeverity.Error
      : vscode.DiagnosticSeverity.Warning;

    const fpLabel = finding.confidence_label || 'unknown';
    const diag = new vscode.Diagnostic(
      anchorRange,
      `[Fray] Bypass: ${truncate(finding.payload, 60)} ` +
      `(confidence: ${finding.bypass_confidence}%, FP: ${fpLabel})`,
      severity
    );
    diag.source = 'Fray';
    diag.code = `status-${finding.status}`;
    diagnostics.push(diag);
  }

  if (diagnostics.length > 0) {
    diagnosticCollection.set(doc.uri, diagnostics);
  }

  // Show summary notification for scan/test/bypass
  if (command === 'scan' || command === 'test' || command === 'bypass') {
    const summary = results.summary;
    if (summary) {
      const msg = `Fray: ${summary.passed || 0} bypass(es), ${summary.blocked || 0} blocked, block rate: ${summary.block_rate || 'N/A'}`;
      if (summary.passed > 0) {
        vscode.window.showWarningMessage(msg, 'Show Results', 'Open Report').then((choice: string | undefined) => {
          if (choice === 'Show Results') { outputChannel.show(); }
          if (choice === 'Open Report') { showReportWebview(context); }
        });
      }
    }
  }
}

// ---------------------------------------------------------------------------
// JSON parser (extracts JSON from mixed output)
// ---------------------------------------------------------------------------

function tryParseJson(text: string): any | null {
  // Try direct parse first
  try {
    return JSON.parse(text.trim());
  } catch { /* continue */ }

  // Find the last JSON object in the output (fray may print text before JSON)
  const braceStart = text.lastIndexOf('\n{');
  if (braceStart >= 0) {
    try {
      return JSON.parse(text.substring(braceStart).trim());
    } catch { /* continue */ }
  }

  // Try finding first { to last }
  const firstBrace = text.indexOf('{');
  const lastBrace = text.lastIndexOf('}');
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    try {
      return JSON.parse(text.substring(firstBrace, lastBrace + 1));
    } catch { /* continue */ }
  }

  return null;
}

// ---------------------------------------------------------------------------
// HTML Report Webview
// ---------------------------------------------------------------------------

function showReportWebview(context: vscode.ExtensionContext) {
  if (!lastResults) {
    vscode.window.showInformationMessage('No scan results yet. Run a Fray command first.');
    return;
  }

  const panel = vscode.window.createWebviewPanel(
    'frayReport',
    `Fray Report: ${lastResults.target}`,
    vscode.ViewColumn.One,
    { enableScripts: false }
  );

  panel.webview.html = buildReportHtml(lastResults.command, lastResults.target, lastResults.data);
}

function buildReportHtml(command: string, target: string, data: any): string {
  const findings: FrayFinding[] = data.test_results || data.results || [];
  const summary = data.summary || {};
  const bypasses = findings.filter(f => !f.blocked);
  const blocked = findings.filter(f => f.blocked);
  const timestamp = new Date().toLocaleString();

  const bypassRows = bypasses.map((f, i) => `
    <tr>
      <td>${i + 1}</td>
      <td><code>${escHtml(truncate(f.payload, 80))}</code></td>
      <td>${f.status}</td>
      <td>${f.bypass_confidence}%</td>
      <td>${f.fp_score}%</td>
      <td>${f.elapsed_ms}ms</td>
    </tr>`).join('');

  const blockedRows = blocked.slice(0, 20).map((f, i) => `
    <tr class="blocked">
      <td>${i + 1}</td>
      <td><code>${escHtml(truncate(f.payload, 80))}</code></td>
      <td>${f.status}</td>
      <td>${f.elapsed_ms}ms</td>
    </tr>`).join('');

  const blockRate = summary.block_rate || 'N/A';
  const totalTested = summary.total_tested || findings.length;
  const passedCount = summary.passed || bypasses.length;
  const blockedCount = summary.blocked || blocked.length;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px; color: var(--vscode-foreground); background: var(--vscode-editor-background); }
  h1 { font-size: 1.6em; margin-bottom: 4px; }
  h2 { font-size: 1.2em; margin-top: 24px; border-bottom: 1px solid var(--vscode-widget-border); padding-bottom: 6px; }
  .meta { color: var(--vscode-descriptionForeground); font-size: 0.9em; margin-bottom: 16px; }
  .stats { display: flex; gap: 16px; flex-wrap: wrap; margin: 16px 0; }
  .stat-card { background: var(--vscode-editorWidget-background); border: 1px solid var(--vscode-widget-border); border-radius: 8px; padding: 14px 20px; min-width: 120px; text-align: center; }
  .stat-card .value { font-size: 2em; font-weight: 700; }
  .stat-card .label { font-size: 0.85em; color: var(--vscode-descriptionForeground); margin-top: 2px; }
  .stat-card.danger .value { color: var(--vscode-errorForeground); }
  .stat-card.success .value { color: var(--vscode-testing-iconPassed); }
  .stat-card.info .value { color: var(--vscode-notificationsInfoIcon-foreground); }
  table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.9em; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--vscode-widget-border); }
  th { background: var(--vscode-editorWidget-background); font-weight: 600; }
  tr:hover { background: var(--vscode-list-hoverBackground); }
  tr.blocked { opacity: 0.6; }
  code { background: var(--vscode-textCodeBlock-background); padding: 2px 5px; border-radius: 3px; font-size: 0.85em; word-break: break-all; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.8em; font-weight: 600; }
  .badge-danger { background: var(--vscode-inputValidation-errorBackground); color: var(--vscode-errorForeground); }
  .badge-warn { background: var(--vscode-inputValidation-warningBackground); color: var(--vscode-editorWarning-foreground); }
  .badge-ok { background: var(--vscode-inputValidation-infoBackground); color: var(--vscode-notificationsInfoIcon-foreground); }
  .empty { color: var(--vscode-descriptionForeground); font-style: italic; padding: 20px; text-align: center; }
</style>
</head>
<body>
  <h1>Fray ${escHtml(command.toUpperCase())} Report</h1>
  <div class="meta">Target: <strong>${escHtml(target)}</strong> &mdash; ${escHtml(timestamp)}</div>

  <div class="stats">
    <div class="stat-card info"><div class="value">${totalTested}</div><div class="label">Total Tested</div></div>
    <div class="stat-card danger"><div class="value">${passedCount}</div><div class="label">Bypassed</div></div>
    <div class="stat-card success"><div class="value">${blockedCount}</div><div class="label">Blocked</div></div>
    <div class="stat-card"><div class="value">${blockRate}</div><div class="label">Block Rate</div></div>
  </div>

  <h2>Bypasses (${bypasses.length})</h2>
  ${bypasses.length > 0 ? `
  <table>
    <thead><tr><th>#</th><th>Payload</th><th>Status</th><th>Confidence</th><th>FP Score</th><th>Time</th></tr></thead>
    <tbody>${bypassRows}</tbody>
  </table>` : '<div class="empty">No bypasses found &mdash; WAF blocked all payloads.</div>'}

  <h2>Blocked (${blocked.length})</h2>
  ${blocked.length > 0 ? `
  <table>
    <thead><tr><th>#</th><th>Payload</th><th>Status</th><th>Time</th></tr></thead>
    <tbody>${blockedRows}</tbody>
  </table>
  ${blocked.length > 20 ? `<div class="meta">Showing first 20 of ${blocked.length} blocked payloads.</div>` : ''}` : '<div class="empty">No blocked payloads.</div>'}

  <h2>Raw JSON</h2>
  <details><summary>Click to expand</summary><pre><code>${escHtml(JSON.stringify(data, null, 2))}</code></pre></details>
</body>
</html>`;
}

function escHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ---------------------------------------------------------------------------
// Stop running process
// ---------------------------------------------------------------------------

function stopRunning() {
  if (activeProcess) {
    activeProcess.kill('SIGTERM');
    const proc = activeProcess;
    global.setTimeout(() => {
      if (proc && !proc.killed) {
        proc.kill('SIGKILL');
      }
    }, 3000);
    activeProcess = null;
    statusBarItem.text = '$(shield) Fray';
    statusBarItem.backgroundColor = undefined;
    outputChannel.appendLine('\n━━━ Scan stopped by user ━━━');
    vscode.window.showInformationMessage('Fray scan stopped.');
  }
}

// ---------------------------------------------------------------------------
// Check installation
// ---------------------------------------------------------------------------

async function checkFrayInstalled() {
  const pythonPath = vscode.workspace.getConfiguration('fray').get<string>('pythonPath', 'python');
  try {
    cp.execSync(`${pythonPath} -m fray --version`, { timeout: 10000, stdio: 'pipe' });
  } catch {
    const choice = await vscode.window.showWarningMessage(
      'Fray does not appear to be installed. Install it with: pip install fray-security',
      'Install Now', 'Set Python Path', 'Dismiss'
    );
    if (choice === 'Install Now') {
      const terminal = vscode.window.createTerminal('Fray Install');
      terminal.show();
      terminal.sendText(`${pythonPath} -m pip install fray-security`);
    } else if (choice === 'Set Python Path') {
      vscode.commands.executeCommand('workbench.action.openSettings', 'fray.pythonPath');
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function truncate(s: string, max: number): string {
  return s.length > max ? s.substring(0, max - 3) + '...' : s;
}


// ---------------------------------------------------------------------------
// Tree View: Results
// ---------------------------------------------------------------------------

class FrayResultsProvider implements vscode.TreeDataProvider<FrayTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<FrayTreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private command = '';
  private target = '';
  private findings: FrayFinding[] = [];
  private rawResults: any = null;

  setResults(command: string, target: string, findings: FrayFinding[], raw: any) {
    this.command = command;
    this.target = target;
    this.findings = findings;
    this.rawResults = raw;
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: FrayTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: FrayTreeItem): FrayTreeItem[] {
    if (!this.target) {
      return [new FrayTreeItem('No results yet', 'Run a Fray command to see results', vscode.TreeItemCollapsibleState.None)];
    }

    if (!element) {
      // Root level: summary + findings
      const items: FrayTreeItem[] = [];

      // Summary node
      const summary = this.rawResults?.summary;
      if (summary) {
        const sumItem = new FrayTreeItem(
          `${this.command.toUpperCase()}: ${this.target}`,
          `${summary.total_tested || 0} tested, ${summary.passed || 0} bypassed, block rate: ${summary.block_rate || 'N/A'}`,
          vscode.TreeItemCollapsibleState.None
        );
        sumItem.iconPath = new vscode.ThemeIcon('shield');
        items.push(sumItem);
      }

      // Bypasses section
      const bypasses = this.findings.filter(f => !f.blocked);
      if (bypasses.length > 0) {
        const bypassNode = new FrayTreeItem(
          `Bypasses (${bypasses.length})`,
          '',
          vscode.TreeItemCollapsibleState.Expanded
        );
        bypassNode.iconPath = new vscode.ThemeIcon('warning');
        bypassNode.children = bypasses.map(f => this.findingToItem(f));
        items.push(bypassNode);
      }

      // Blocked section
      const blocked = this.findings.filter(f => f.blocked);
      if (blocked.length > 0) {
        const blockedNode = new FrayTreeItem(
          `Blocked (${blocked.length})`,
          '',
          vscode.TreeItemCollapsibleState.Collapsed
        );
        blockedNode.iconPath = new vscode.ThemeIcon('pass');
        blockedNode.children = blocked.map(f => this.findingToItem(f));
        items.push(blockedNode);
      }

      return items;
    }

    return element.children || [];
  }

  private findingToItem(finding: FrayFinding): FrayTreeItem {
    const icon = finding.blocked ? '$(pass)' : finding.bypass_confidence >= 70 ? '$(error)' : '$(warning)';
    const status = finding.blocked ? 'BLOCKED' : 'PASSED';
    const label = truncate(finding.payload, 50);
    const desc = `${status} ${finding.status} | conf: ${finding.bypass_confidence}% | FP: ${finding.fp_score}%`;

    const item = new FrayTreeItem(label, desc, vscode.TreeItemCollapsibleState.None);
    item.iconPath = new vscode.ThemeIcon(
      finding.blocked ? 'pass' : finding.bypass_confidence >= 70 ? 'error' : 'warning'
    );
    item.tooltip = new vscode.MarkdownString(
      `**Payload:** \`${finding.payload}\`\n\n` +
      `**Status:** ${finding.status}\n` +
      `**Blocked:** ${finding.blocked}\n` +
      `**Reflected:** ${finding.reflected}\n` +
      `**Bypass Confidence:** ${finding.bypass_confidence}%\n` +
      `**FP Score:** ${finding.fp_score}% (${finding.confidence_label})\n` +
      (finding.fp_reasons?.length ? `**FP Reasons:** ${finding.fp_reasons.join(', ')}\n` : '') +
      `**Response Time:** ${finding.elapsed_ms}ms`
    );
    return item;
  }
}

class FrayTreeItem extends vscode.TreeItem {
  children?: FrayTreeItem[];

  constructor(
    label: string,
    desc: string,
    collapsibleState: vscode.TreeItemCollapsibleState
  ) {
    super(label, collapsibleState);
    this.description = desc;
  }
}

// ---------------------------------------------------------------------------
// Tree View: History
// ---------------------------------------------------------------------------

class FrayHistoryProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<vscode.TreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private entries: FrayHistoryEntry[] = [];

  constructor(private context: vscode.ExtensionContext) {
    this.entries = context.globalState.get<FrayHistoryEntry[]>('fray.history', []);
  }

  addEntry(entry: FrayHistoryEntry, context: vscode.ExtensionContext) {
    this.entries.unshift(entry);
    if (this.entries.length > 50) { this.entries = this.entries.slice(0, 50); }
    context.globalState.update('fray.history', this.entries);
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(): vscode.TreeItem[] {
    if (this.entries.length === 0) {
      return [new vscode.TreeItem('No scan history')];
    }

    return this.entries.map(entry => {
      const time = new Date(entry.timestamp).toLocaleString();
      const item = new vscode.TreeItem(
        `${entry.command}: ${entry.target}`,
        vscode.TreeItemCollapsibleState.None
      );
      item.description = `${time} (${entry.resultCount} findings)`;
      item.iconPath = new vscode.ThemeIcon(
        entry.command === 'scan' ? 'shield' :
        entry.command === 'test' ? 'beaker' :
        entry.command === 'recon' ? 'search' :
        entry.command === 'osint' ? 'globe' : 'key'
      );
      return item;
    });
  }
}
