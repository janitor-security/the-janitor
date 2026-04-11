/**
 * The Janitor — VS Code Extension
 *
 * Launches `janitor serve --mcp` as a stdio MCP server and exposes
 * real-time antipattern diagnostics via `janitor_lint_file` on file save.
 *
 * Architecture:
 *   1. `activate()` spawns the `janitor serve --mcp` child process.
 *   2. A JSON-RPC 2.0 client talks over stdin/stdout of that process.
 *   3. On each `onDidSaveTextDocument` event, `janitor_lint_file` is called
 *      with the file path and current buffer contents.
 *   4. Findings are rendered as VS Code Diagnostics (squiggles + Problems panel).
 */

import * as vscode from 'vscode';
import { ChildProcess, spawn } from 'child_process';
import * as readline from 'readline';

let janitorProcess: ChildProcess | undefined;
let diagnosticCollection: vscode.DiagnosticCollection;
let pendingCallbacks = new Map<number, (result: unknown) => void>();
let nextId = 1;

// ---------------------------------------------------------------------------
// Extension lifecycle
// ---------------------------------------------------------------------------

export function activate(context: vscode.ExtensionContext): void {
    diagnosticCollection = vscode.languages.createDiagnosticCollection('janitor');
    context.subscriptions.push(diagnosticCollection);

    startMcpServer(context);

    // Lint on save.
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((doc) => {
            lintDocument(doc);
        }),
    );

    // Manual scan command.
    context.subscriptions.push(
        vscode.commands.registerCommand('janitor.lintFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                lintDocument(editor.document);
            }
        }),
    );
}

export function deactivate(): void {
    janitorProcess?.kill();
    diagnosticCollection?.clear();
}

// ---------------------------------------------------------------------------
// MCP server lifecycle
// ---------------------------------------------------------------------------

function getJanitorPath(): string {
    const cfg = vscode.workspace.getConfiguration('janitor');
    return cfg.get<string>('serverPath', 'janitor');
}

function startMcpServer(context: vscode.ExtensionContext): void {
    const bin = getJanitorPath();

    try {
        janitorProcess = spawn(bin, ['serve', '--mcp'], {
            stdio: ['pipe', 'pipe', 'pipe'],
        });
    } catch {
        vscode.window.showWarningMessage(
            `Janitor: could not start MCP server (binary: ${bin}). Install janitor and set janitor.serverPath.`,
        );
        return;
    }

    const rl = readline.createInterface({ input: janitorProcess.stdout! });
    rl.on('line', (line: string) => {
        try {
            const msg = JSON.parse(line) as { id?: number; result?: unknown; error?: unknown };
            if (msg.id !== undefined) {
                const cb = pendingCallbacks.get(msg.id);
                if (cb) {
                    pendingCallbacks.delete(msg.id);
                    cb(msg.result ?? msg.error);
                }
            }
        } catch {
            // Ignore malformed lines.
        }
    });

    janitorProcess.stderr?.on('data', (_d: Buffer) => {
        // Suppress — MCP servers emit startup diagnostics on stderr.
    });

    janitorProcess.on('exit', () => {
        janitorProcess = undefined;
    });

    // Send initialize.
    sendRpc('initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'janitor-vscode', version: '0.1.0' },
    }).catch(() => {/* best-effort */});

    context.subscriptions.push({ dispose: deactivate });
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 transport
// ---------------------------------------------------------------------------

function sendRpc(method: string, params: unknown): Promise<unknown> {
    return new Promise((resolve) => {
        if (!janitorProcess?.stdin?.writable) {
            resolve(null);
            return;
        }
        const id = nextId++;
        pendingCallbacks.set(id, resolve);
        const msg = JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n';
        janitorProcess.stdin!.write(msg);
    });
}

// ---------------------------------------------------------------------------
// File linting
// ---------------------------------------------------------------------------

async function lintDocument(doc: vscode.TextDocument): Promise<void> {
    if (!janitorProcess) {
        return;
    }
    const cfg = vscode.workspace.getConfiguration('janitor');
    if (!cfg.get<boolean>('enableOnSave', true)) {
        return;
    }

    const result = await sendRpc('tools/call', {
        name: 'janitor_lint_file',
        arguments: {
            path: doc.fileName,
            contents: doc.getText(),
        },
    }) as { content?: Array<{ text: string }> } | null;

    if (!result) {
        return;
    }

    // Unwrap MCP content envelope.
    let inner: { findings?: JanitorFinding[]; is_clean?: boolean } = {};
    try {
        const text = (result as { content?: Array<{ text: string }> }).content?.[0]?.text ?? '';
        inner = JSON.parse(text);
    } catch {
        return;
    }

    const diagnostics: vscode.Diagnostic[] = (inner.findings ?? []).map((f: JanitorFinding) => {
        const line = Math.max(0, (f.line ?? 1) - 1);
        const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
        const sev =
            f.id.startsWith('security:')
                ? vscode.DiagnosticSeverity.Error
                : vscode.DiagnosticSeverity.Warning;
        const diag = new vscode.Diagnostic(range, `[Janitor] ${f.id}`, sev);
        diag.source = 'janitor';
        diag.code = f.id;
        return diag;
    });

    diagnosticCollection.set(doc.uri, diagnostics);
}

interface JanitorFinding {
    id: string;
    file?: string;
    line?: number;
}
