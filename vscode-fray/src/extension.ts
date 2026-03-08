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
    vscode.commands.registerCommand('fray.scanFromSelection', () => runFromSelection('scan', context)),
    vscode.commands.registerCommand('fray.quickPick', () => showQuickPick(context)),
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
    { label: '$(search) Recon URL', description: 'Reconnaissance: tech, headers, DNS, certs', detail: 'fray recon' },
    { label: '$(globe) OSINT Domain', description: 'OSINT: whois, emails, GitHub, typosquatting', detail: 'fray osint' },
    { label: '$(key) Leak Search', description: 'Search leaked credentials (GitHub + HIBP)', detail: 'fray leak' },
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

  if (command === 'scan' || command === 'test') {
    const category = config.get<string>('defaultCategory', 'xss');
    const maxPayloads = config.get<number>('maxPayloads', 5);
    const timeout = config.get<number>('timeout', 8);
    const delay = config.get<number>('delay', 0.5);

    args.push('-c', category, '-m', String(maxPayloads), '-t', String(timeout), '-d', String(delay));

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

  // Show summary notification for scan/test
  if (command === 'scan' || command === 'test') {
    const summary = results.summary;
    if (summary) {
      const msg = `Fray: ${summary.passed || 0} bypass(es), ${summary.blocked || 0} blocked, block rate: ${summary.block_rate || 'N/A'}`;
      if (summary.passed > 0) {
        vscode.window.showWarningMessage(msg, 'Show Results').then((choice: string | undefined) => {
          if (choice === 'Show Results') { outputChannel.show(); }
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
