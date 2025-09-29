import * as vscode from 'vscode';
import * as path from "path";
import * as fs from "fs";
import * as fsp from "fs/promises";
import * as os from 'os';
import * as crypto from 'crypto';
import * as net from 'net';
import { Worker }    from 'worker_threads';
import { spawn } from 'child_process';
import { createHash } from "crypto";

import {
	Settings,
	getCallstacksGraphParams, mergeCallstacksIntoGraphParams,
	SearchTemplate,
	ScopeSummary, FunctionResult, Loc, FunctionOverride, FunctionRelationship, FunctionIdObj, FilteredFunctionState,
	StringHashmap, BooleanHashmap, CallGraphHashmap, CallstacksEdgeColorsHashmap, FiletLineColumnOffsetHashmap, 
	CallGraph, graphGroup, graphNode, graphEdge, SourceFilesHashmap, ScopeDefinitionsHashmap, RelatedCallstacksHashmap, funcStateVarReadWrittenMappingHashmap, ScopeDefinition,
	DecorationRange, DecorationsData,
	WorkerResult
} from './types';

export enum FunctionFilterMode {
	Identifier = "identifier",
	Content = "content"
}




class Index {
  private byFile = new Map<string, FunctionResult[]>();

  constructor(funcs: Iterable<FunctionResult>) {
    for (const f of funcs) {
      const base = f.filepath.split("#", 1)[0]; // or better: store base when you create FunctionResult
      if (!this.byFile.has(base)) this.byFile.set(base, []);
      this.byFile.get(base)!.push(f);
    }
    // sort each file’s funcs by startLine
    for (const arr of this.byFile.values()) arr.sort((a, b) => a.startLine - b.startLine);
  }

  // O(log k) lookup
  getByLine(basePath: string, line: number): FunctionResult | null {
    const arr = this.byFile.get(basePath);
    if (!arr || arr.length === 0) return null;

    // upper-bound: first startLine > line
    let lo = 0, hi = arr.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (arr[mid].startLine <= line) lo = mid + 1; else hi = mid;
    }
    const i = lo - 1;
    if (i >= 0) {
      const cand = arr[i];
      if (cand.startLine === cand.endLine || (cand.startLine <= line && line <= cand.endLine)) {
        return cand;
      }
    }
    return null;
  }
}


import { StaticAnalysisCodeLensProvider } from './codelens';
// import { log } from 'console';

let logger = vscode.window.createOutputChannel("Static Analysis Extension Output");

async function getCopilotContext() {
	let ctx: string = `@workspace  
You are a security researcher specializing in static analysis across programming languages and frameworks.  
Review the codebase for security vulnerabilities, insecure patterns, logic flaws, and risky edge cases.

🔎 Focus areas (not exhaustive):
- Input vulnerabilities: injection attacks (e.g., SQLi, command, path, XSS, SSRF, JSON, XML)
- Access control flaws: IDOR, broken auth, privilege escalation, trust boundary violations
- Insecure cryptography: hardcoded secrets, weak algorithms, misuse of crypto APIs
- API and third-party risks: unsafe deserialization, excessive permissions, dynamic imports, outdated libraries
- Logic errors: race conditions, TOCTOU, off-by-one, broken assumptions, concurrency bugs
- State/flow issues: unsafe state sharing, unexpected side effects, overly permissive defaults
- Data leaks: sensitive info in logs, URLs, error messages, or exposed responses
- Misuse of language/runtime features that affect control flow, input handling, or trust boundaries
- Untrusted user inputs: headers, parameters, cookies, etc. (check for validation, sanitization, encoding) - sources & sinks

📁 Use static artifacts in \`.vscode/ext-static-analysis/\` for deeper context:
- \`functions_html.json\` → function scopes, state variables, decorators
- \`callstacks.json\` → call chains and input flow paths
- \`decorators.json\` → overlays indicating exposure, sinks, or static flags

🧪 Instructions:
- Reference specific functions, lines, or call paths
- Rate severity: Low / Medium / High / Critical
- Recommend practical remediations (minimal, language-appropriate)
- Reference OWASP, CWE, or CVEs if applicable
- Avoid speculation — findings must be grounded in code or static metadata

🎯 Note:
Apply knowledge of common weaknesses and patterns specific to the language or framework in use — even if not explicitly mentioned. Focus on how untrusted input or unsafe assumptions might lead to security issues or fragile code.

	`;

	let copilotContextFilePath = path.join(vscode.workspace.workspaceFolders?.[0].uri.fsPath || '', '.vscode', 'ext-static-analysis', 'copilot_ctx.txt');
	if (fs.existsSync(copilotContextFilePath)) {
		ctx = fs.readFileSync(copilotContextFilePath, 'utf-8');
	} else {
		// create the file if it does not exist
		fs.writeFileSync(copilotContextFilePath, ctx, 'utf-8');
	}

	return ctx
}

async function sendToCopilotChat(message: string) {
	vscode.commands.executeCommand('workbench.action.chat.open', message);
}

function getAllFiles(dirPath: string): string[] {
  let entries = fs.readdirSync(dirPath, { withFileTypes: true });

  let files = entries.flatMap(entry => {
    const fullPath = path.join(dirPath, entry.name);
    return entry.isDirectory()
      ? getAllFiles(fullPath)
      : fullPath;
  });

  return files;
}

async function sendFileToScan(filePath: string, cmd: string = "") {
	// check if file or folder
	if (!fs.existsSync(filePath)) {
		logger.appendLine(`[Extension] File or folder does not exist: ${filePath}`);
		return;
	}

	let files = []
	if (fs.lstatSync(filePath).isDirectory()) {
		logger.appendLine(`[Extension] Scanning directory: ${filePath}`);
		// If it's a directory, read all files in it
		files = getAllFiles(filePath)
		// files = files.filter(file => fs.lstatSync(file).isFile()); // filter out directories
		files = files.map(file => {
			return `${cmd}~${file}`
		})
		if (files.length === 0) {
			return;
		}
	} else {
		files = [`${cmd}~${filePath}`]
	}

	// Calculate chunk size based on max file path length
	// This ensures we stay under typical socket buffer limits
	const MAX_BUFFER_SIZE = 65536; // 64KB typical socket buffer
	const longestPath = Math.max(...files.map(f => f.length));
	const CHUNK_SIZE = Math.floor(MAX_BUFFER_SIZE / (longestPath + 1)); // +1 for newline

	// Split files into chunks to avoid socket buffer limits
	const fileChunks = [];
	for (let i = 0; i < files.length; i += CHUNK_SIZE) {
		fileChunks.push(files.slice(i, i + CHUNK_SIZE));
	}

	// Process each chunk sequentially
	for (const chunk of fileChunks) {
		const client = new net.Socket();
		client.connect(9999, '127.0.0.1', () => {
			logger.appendLine(`[Extension] Connected to static analysis server, sending ${chunk.join(', ')}`);
			client.write(chunk.join('\n')); 
			client.end(); // Close after sending
		});

		client.on('error', (err) => {
			logger.appendLine(`[Extension] Socket error: ${err.message}`);
		});

		// Wait for connection to complete before processing next chunk
		await new Promise((resolve) => {
			client.on('close', resolve);
		});
	
	}
}


export async function activate(context: vscode.ExtensionContext) {
	const provider = new StaticAnalysisViewProvider(context.extensionUri);
	vscode.window.registerWebviewViewProvider('static-analysis-view', provider, { webviewOptions: { retainContextWhenHidden: true } })
	provider._context = context

	const watcher = vscode.workspace.createFileSystemWatcher('**/*');
    // Register event listeners
    watcher.onDidChange((uri) => {
        vscode.window.showInformationMessage(`File changed: ${uri.fsPath}`);
        provider.sourceFilesCache[uri.fsPath] = undefined
    });
	context.subscriptions.push(watcher);



	// context.subscriptions.push(
	// 	vscode.commands.registerCommand('staticAnalysis.load', () => {
	// 		// CatCodingPanel.createOrShow(context.extensionUri);
	// 	})
	// );

	context.subscriptions.push(vscode.commands.registerCommand('staticAnalysis.scanFileOrFolderFunctionNames', async (uri: vscode.Uri) => {
		await sendFileToScan(uri.fsPath, 'fnsOnly');
	}));

	context.subscriptions.push(vscode.commands.registerCommand('staticAnalysis.scanFileOrFolderFullPriority', (uri: vscode.Uri) => {
		sendFileToScan(uri.fsPath, 'fnsOnly');
		sendFileToScan(uri.fsPath, "1");
	}));

	context.subscriptions.push(vscode.commands.registerCommand('staticAnalysis.scanFileOrFolderFull', (uri: vscode.Uri) => {
		sendFileToScan(uri.fsPath, 'fnsOnly');
		sendFileToScan(uri.fsPath);
	}));



	context.subscriptions.push(
		vscode.commands.registerCommand('static-analysis.navigateToFunction', (f: FunctionResult) => {
			provider.showFunction(f.id)
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('static-analysis.references', (f: FunctionResult) => {
			provider.showReferences(f)
		})
	);

	let last_manual_mapped_func: string | null = null
	context.subscriptions.push(
		vscode.commands.registerCommand('static-analysis.manuallyMapFunctionRelationship', (f: FunctionResult) => {
			provider.manuallyMapFunctionRelationship(f.id)
		})
	);
	
	context.subscriptions.push(
		vscode.commands.registerCommand('staticAnalysis.toggleTextHighlights', async () => {
			const config = vscode.workspace.getConfiguration('static-analysis');
			const currentValue = config.get<boolean>('enableTextHighlights');

			await config.update('enableTextHighlights', !currentValue, vscode.ConfigurationTarget.Workspace).then(
				() => {
					// Optionally, show a message to the user
					vscode.window.showInformationMessage(
						`static-analysis.enableTextHighlights is now set to: ${!currentValue}`
					);
				},
				(error) => {
				  vscode.window.showErrorMessage(`Failed to update setting: ${error}`);
				}
			)
		})
	)

	// await provider.loadFunctionsAndScopeInfo()
	// context.subscriptions.push(
	// 	vscode.languages.registerCodeLensProvider(
	// 		// ["solidity", "python", "c", "cpp", "javascript", "typescript", "java", "go"],
	// 		{ scheme: 'file' },
	// 		// SHOULD ALSO REGISTER OTHER LANGUGES CODELENSES
	// 		new StaticAnalysisCodeLensProvider({ pattern: '**/*' }, provider.functionDefinitions.filter(f => { return !f.is_inherited }), provider.getAuditCommentsLineOffset, provider.getFileLines, provider.sourceFilesCache)
	// 	)
	// );

	let resetTextHighlights = configureTextHighlights(provider)
	context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration(event => {
            if (event.affectsConfiguration('static-analysis.enableUnsafeEval')) {
                // Reload the webview if the specific setting has changed
				provider.reloadWebview()
            }

			if (event.affectsConfiguration('static-analysis.enableTextHighlights')) {
				if (resetTextHighlights) {
					resetTextHighlights()
				}
			}
        })
    );


	// send data to streaming analysis script
	vscode.workspace.onDidOpenTextDocument((document) => {
        const filePath = document.fileName;

		sendFileToScan(filePath, 'fnsOnly');
		sendFileToScan(filePath);
    });

	// monitor for changes in data files
	// send every tick to deal with reload sync issues, can refactor if perforamnce is not acceptable
	setInterval(() => {
		if (provider._view) {
			provider._view.webview.postMessage({ command: "hasNewData", value: fs.existsSync(provider.hasNewDataFilePath) });
		}
	}, 1000);
}


async function showContentInBrowser(html: string) {	
	const hash = crypto.createHash('sha256');
	hash.update(html);

	const filename = hash.digest('hex') + '.html';

	// Write content to a temporary file
	const homeDir = os.homedir();
	// make dir if it doesn't exist + ~/tmp
	const tmpDir = path.join(homeDir, 'tmp');
	if (!fs.existsSync(tmpDir)) {
		fs.mkdirSync(tmpDir);
	}
	const tempFilePath = path.join(tmpDir, filename);
	fs.writeFileSync(tempFilePath, html, { encoding: 'utf8' });

	// Convert the path to a file URI
	const tempFileUri = vscode.Uri.file(tempFilePath);

	// Open the file in the default browser
	const success = await vscode.env.openExternal(tempFileUri);
	if (!success) {
		vscode.window.showErrorMessage("Failed to open the browser. Please check your system configuration.");
	}
}


function configureTextHighlights(provider: StaticAnalysisViewProvider) {
	const activeDecorations: Map<vscode.TextEditor, vscode.TextEditorDecorationType[]> = new Map();

	if (vscode.workspace.workspaceFolders) {
		let decorationsFilePath = path.join(vscode.workspace.workspaceFolders[0].uri.path, ".vscode", "ext-static-analysis", "decorations.json") // Update this path as needed
		
		if (!fs.existsSync(decorationsFilePath)) {
			console.error("Decorations file does not exist:", decorationsFilePath);
			return;
		}

		function parseStyles(style: string): vscode.DecorationRenderOptions[] {
			const options: vscode.DecorationRenderOptions[] = [];
	
			style.split(";").forEach((rule) => {
				rule = rule.trim()
				let option: vscode.DecorationRenderOptions = {}
				if (rule.startsWith("::before")) {
					const contentText = rule.split("~")[1].trim();
					const color = rule.split("~")[2].trim();
					option.before = { 
						contentText: contentText,
						color: color 
					};
				} else if (rule.startsWith("::after")) {
					const contentText = rule.split("~")[1].trim();
					const color = rule.split("~")[2].trim();
					option.after = { 
						contentText: contentText,
						color: color
					}
				} else {
					const [key, value] = rule.split(":").map((part) => part.trim());
					if (key && value) {
						switch (key) {
							case "border":
								option.border = value;
								break;
							case "background-color":
								option.backgroundColor = value;
								break;
							case "color":
								option.color = value;
								break;
							case "text-decoration":
								option.textDecoration = value;
								break;
							case "opacity":
								option.opacity = value;
							// Add more cases as needed
						}
					}
				}
				options.push(option);
			});
	
			return options;
		}
	
		function clearDecorations(editor: vscode.TextEditor) {
			const decorations = activeDecorations.get(editor);
			if (decorations) {
				decorations.forEach((type) => {
					editor.setDecorations(type, []); // Clear the decorations
				});
				activeDecorations.delete(editor); // Remove from tracking
			}
		}

		/**
		 * Apply decorations to the provided editor based on the decoration data.
		 */
		function applyDecorations(editor: vscode.TextEditor, decorations: { type: vscode.TextEditorDecorationType, range: DecorationRange }[]) {
			// Group ranges by decoration type
			const decorationRanges: Map<vscode.TextEditorDecorationType, vscode.Range[]> = new Map();
		
			decorations.forEach(({ type, range }) => {
				let offset = provider.getAuditCommentsLineOffset(editor.document.uri.fsPath, range.line + 1)
				
				const decorationRange = new vscode.Range(
					new vscode.Position(range.line + offset - 1, range.start - 1),
					new vscode.Position(range.line + offset - 1, range.end - 1)
				);
		
				if (!decorationRanges.has(type)) {
					decorationRanges.set(type, []);
				}
		
				decorationRanges.get(type)?.push(decorationRange);
			});
		
			// Apply all ranges for each decoration type
			const appliedTypes: vscode.TextEditorDecorationType[] = [];
			decorationRanges.forEach((ranges, type) => {
				editor.setDecorations(type, ranges);
				if (type && !appliedTypes.includes(type)) {
					appliedTypes.push(type);
				}
			});

			activeDecorations.set(editor, appliedTypes);
		}
	
		/**
		 * Load decorations from the JSON file and apply them to all open editors.
		 */
		async function loadDecorations(filePath: string = decorationsFilePath) {
			// if static-analysis.enableTextHighlights is enabled
			const decorationTypes: Map<string, vscode.TextEditorDecorationType> = new Map();
			try {
				const rawData = await fs.readFileSync(filePath, 'utf-8');
				let decorationsJson: DecorationsData = JSON.parse(rawData);

				if (vscode.workspace.workspaceFolders) {
					// make filepaths absolute if they are relative
					let workspaceFolder = vscode.workspace.workspaceFolders[0].uri.path
					for (let [filePath, decorations] of Object.entries(decorationsJson)) {
						if (!filePath.startsWith(workspaceFolder)) {
							const absolutePath = path.join(workspaceFolder, filePath)
							decorationsJson[absolutePath] = decorations
							delete decorationsJson[filePath]
						}
					}
				}

	
				const decorations: { type: vscode.TextEditorDecorationType, range: DecorationRange }[] = [];
				vscode.window.visibleTextEditors.forEach((editor) => {
					clearDecorations(editor); // Clear existing decorations
					const filePath = editor.document.fileName;
					const decorationsForFile = decorationsJson[filePath];
	
					if (decorationsForFile) {
						for (const [style_str, ranges] of Object.entries(decorationsForFile)) {
							let decorationType = decorationTypes.get(style_str);
							if (!decorationType) {
								let styles: vscode.DecorationRenderOptions[] = parseStyles(style_str);
								for (let style of styles) {
									const decorationOptions = style;
									decorationType = vscode.window.createTextEditorDecorationType(decorationOptions);
									decorationTypes.set(style_str, decorationType);

									
									ranges.forEach((range) => {
										if (decorationType) {
											decorations.push({ type: decorationType, range: range });
										}
									});
								}
							}
	

						}

						if (vscode.workspace.getConfiguration('static-analysis').get("enableTextHighlights")) {
							applyDecorations(editor, decorations);
						}
					}
				});
			} catch (error) {
				console.error("Failed to load decorations:", error);
			}
		}
	
		/**
		 * Watch for changes in the decorations JSON file.
		 */
		fs.watch(decorationsFilePath, { persistent: true }, (eventType) => {
			if (eventType === 'change') {
				loadDecorations(decorationsFilePath);
			}
		});
	
		/**
		 * Handle newly opened or active editors.
		 */
		vscode.window.onDidChangeActiveTextEditor((editor) => {
			if (editor) {
				loadDecorations(decorationsFilePath);
			}
		});
	
		// Load decorations initially
		loadDecorations(decorationsFilePath);

		return loadDecorations
	}
}


function getWebviewOptions(extensionUri: vscode.Uri): vscode.WebviewOptions {
	return {
		// Enable javascript in the webview
		enableScripts: true,

		// enable vscode.open (allow opening files)
		enableCommandUris: ['vscode.open'],

		// And restrict the webview to only loading content from our extension's `media` directory.
		localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'media')]
	};
}



// creates WebViewProvider
class StaticAnalysisViewProvider implements vscode.WebviewViewProvider {
	// example code from: https://github.com/microsoft/vscode-extension-samples/blob/main/webview-view-sample/src/extension.ts
	public static readonly viewType = 'staticanalysis.view';

	public DATA_PATH = path.join(".vscode", "ext-static-analysis")
	public DETECTORS_PATH = path.join(".vscode", "ext-detectors", "detector-results.json")

	public _view?: vscode.WebviewView;
	public hasNewDataFilePath: string = path.join(vscode.workspace.workspaceFolders?.[0].uri.fsPath || '', this.DATA_PATH, '_reload_ready.state');
	public _context: vscode.ExtensionContext = {} as vscode.ExtensionContext;
	public helpHTML: string = '';
	public lastManuallyMappedFunction_caller: string | null = null
	public lastManuallyMappedFunction_callee: string | null = null
	public scopeSummaries: ScopeSummary[] = [];
	public functionDefinitions: FunctionResult[] = [];
	public functionOverrides: Map<string, FunctionOverride> = new Map(); // used to store function overrides (i.e.: manually mapped functions)
	public functionDefinitionByFilepath: { [key:string]: boolean} = {}; // used to quickly check if a file has function definitions
	public functionDefinitionsMap: Map<string, FunctionResult> = new Map();
	public functionScopesMap: Map<string, FunctionResult[]> = new Map();
	
	public functionSortedIndex: Index = new Index([]);
	public functionManualRelationship: FunctionRelationship[] = [];  // not making a hashmap because this list should never get too large
	
	private defaultFileLineColumnOffset: FiletLineColumnOffsetHashmap = {}; // used to find column when opening function, primarily when id does not contain column number

	private scopeDefinitionsMap: ScopeDefinitionsHashmap = {}  // can also be used to enumerate scopes themselves
	private callstacks: string[][] = [];
	private callstacksHtml?: string[];
	private func_pair_edge_colors: CallstacksEdgeColorsHashmap = {}
	private decoratorUnicode: string = "";
	private functionSortOption: "Alpha. + Line #" | "Alpha. + SLOC" | "SLOC" | "Alpha. + # Callstacks" | "# Callstacks" = "Alpha. + Line #"

	private searchTemplates: SearchTemplate[] = []

	private funcStateVarReadWrittenMapping: funcStateVarReadWrittenMappingHashmap = {};
	private scopeGraphs: CallGraphHashmap = {};
	private inheritanceGraph: CallGraph = { nodes: [], edges: [] };
	private hasInheritedFunctions: boolean = false;
	private relatedCallstacksHash: RelatedCallstacksHashmap = {};
	// NOTE: excludeRelatedCallstacks is case sensitive, comparing case insensitive would not be accurate for case sensitive languages like JavaScript
	// however, may want to make case insensitive in the future because we are looking for related functions, not necessarily exact matches (case sensitivity may not be important in most cases)
	private settings: Settings = { excludedRelatedCallstacks: ["slitherConstructorConstantVariables", "constructor", "initialize", "initializer", "init", "__init__", "run", "main", "__main__"], manualFunctionRelationshipPath: "", showAllFunctions: false, ctnt_uses_gitignore: false };

	private callstacksGraphCache: CallGraphHashmap = {}; // should use a data structure to separate: groups | nodes | edges ?
	public sourceFilesCache: SourceFilesHashmap = {}

	private currentFilteredFunctionState: FilteredFunctionState = { regexPattern: "", excludeRegexPattern: "", cntRegexPattern: "", filteredFunctionIds: [], hideReviewedState: "Hide Reviewed Except In Scope" }; // sets default
	private codeLensDisposable: vscode.Disposable | null = null;
	private fileDecoratorDisposable: vscode.Disposable | null = null;
	public scannedFiles: { [key: string]: boolean } = {}

	constructor(
		private readonly _extensionUri: vscode.Uri,
	) {
	}

	public registerCodeLensProvider() {
		if (this.codeLensDisposable) {
			this.codeLensDisposable.dispose(); // 🧹 Remove old one
		}

		const newProvider = new StaticAnalysisCodeLensProvider(
			{ pattern: '**/*' },
			this.functionDefinitions.filter(f => !f.is_inherited),
			this.getAuditCommentsLineOffset,
			this.getFileLines,
			this.sourceFilesCache
		);

		this.codeLensDisposable = vscode.languages.registerCodeLensProvider(
			{ scheme: 'file' },
			newProvider
		);

		if (this._context) {
			this._context.subscriptions.push(this.codeLensDisposable);
		}
	}

	
	public registerFileDecoratorProvider() {
		if (this.fileDecoratorDisposable) {
			this.fileDecoratorDisposable.dispose(); // 🧹 Remove old one
		}

			
		const scannedFiles: { [key: string]: boolean} = this.scannedFiles;
		const functionDefinitionByFilepath: { [key: string]: boolean} = this.functionDefinitionByFilepath;
		const fileDecoratorProvider: vscode.FileDecorationProvider = {
			provideFileDecoration(uri: vscode.Uri): vscode.ProviderResult<vscode.FileDecoration> {
				if (scannedFiles[uri.fsPath]) {
					return {
						badge: '🟢',
						tooltip: 'Scanned file'
					};
				} else if (functionDefinitionByFilepath[uri.fsPath]) {
					return {
						badge: '🟠',
						tooltip: 'Contains function definitions'
					};
				}
			}
		};

		this.fileDecoratorDisposable = vscode.window.registerFileDecorationProvider(fileDecoratorProvider)

		if (this._context) {
			this._context.subscriptions.push(this.fileDecoratorDisposable);
		}
	}

	private getFirstWorkspaceFolderPath(): string | null {
		if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
			return vscode.workspace.workspaceFolders[0].uri.fsPath;
		} else {
			vscode.window.showErrorMessage('No workspace folder found.');
			return null;
		}
	}

	private async appendAndCreateFolder(folderName: string) {
		const workspaceFolderPath: string | null = this.getFirstWorkspaceFolderPath();
		if (!workspaceFolderPath) return;

		const newFolderPath = path.join(workspaceFolderPath, folderName);
		if (!fs.existsSync(newFolderPath)) {
			fs.promises.mkdir(newFolderPath, { recursive: true });
			vscode.window.showInformationMessage(`Folder created: ${newFolderPath}`);
		} else {
			vscode.window.showInformationMessage(`Folder already exists: ${newFolderPath}`);
		}

		return newFolderPath;
	}


	private async saveFile(content: string) {
		const fspath = await this.appendAndCreateFolder(`${path.join(this.DATA_PATH, 'graphs')}`) || ""

		if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length == 0) {
			return false;
		}

		vscode.window.showSaveDialog({ defaultUri: vscode.Uri.parse(fspath) }).then(fileUri => {
			if (fileUri) {
				// Write the content to the selected file path
				fs.writeFileSync(fileUri.fsPath, content, 'utf8');
				// Optionally handle after-save actions
			}
		});
	}

	private async loadFile(): Promise<{ filename: string, content: string }> {
		const filepath = await this.appendAndCreateFolder(`${path.join(this.DATA_PATH, 'graphs')}`) || "";

		try {
			const fileUris = await vscode.window.showOpenDialog({ defaultUri: vscode.Uri.parse(filepath) });
			if (fileUris && fileUris[0]) {
				const filePath = fileUris[0].fsPath;
				const content = await fsp.readFile(filePath, 'utf8');
				return { filename: path.basename(filePath), content };
			} else {
				vscode.window.showInformationMessage("No file selected.");
				return { filename: "", content: "" };
			}
		} catch (error) {
			console.error("Error reading file:", error);
			vscode.window.showErrorMessage("Error reading file");
			return { filename: "", content: "" };
		}
	}

	private async saveSettings(): Promise<boolean> {
		// export async function readResults(print : boolean = false) : Promise<boolean> {
		// Verify there is a workspace folder open to run analysis on.
		if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length == 0) {
			return false;
		}

		// Loop for every workspace to read results from.
		for (let i = 0; i < vscode.workspace.workspaceFolders.length; i++) {

			// Obtain our workspace results path.
			const workspacePath = vscode.workspace.workspaceFolders[i].uri.fsPath;

			// If the file exists, we read its contents into memory.
			const resultsPath = path.join(workspacePath, this.DATA_PATH, 'settings.json');
			try {
				fs.writeFileSync(resultsPath, JSON.stringify(this.settings));
			} catch {
				return false;
			}

			return true;
		}

		return false;
	}

	private async saveFunctionInfo(): Promise<boolean> {
		// export async function readResults(print : boolean = false) : Promise<boolean> {
		// Verify there is a workspace folder open to run analysis on.
		if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length == 0) {
			return false;
		}

		// Loop for every workspace to read results from.
		for (let i = 0; i < vscode.workspace.workspaceFolders.length; i++) {

			// Obtain our workspace results path.
			const workspacePath = vscode.workspace.workspaceFolders[i].uri.fsPath;

			// If the file exists, we read its contents into memory.
			const resultsPath = path.join(workspacePath, this.DATA_PATH, 'function_overrides.json');
			try {
				const serializable = Object.fromEntries(
					[...this.functionOverrides.entries()].map(([funcId, override]) => [
						funcId,
						{
							...override,
							decorators_to_add: Array.from(override.decorators_to_add),
							decorators_to_remove: Array.from(override.decorators_to_remove)
						},
					])
					);

				fs.writeFileSync(resultsPath, JSON.stringify(serializable));
			} catch {
				return false;
			}

			return true;
		}

		return false;
	}

	
	private decodeBase64Unicode(str: string) {
		const text = atob(str);
		const bytes = new Uint8Array(text.length);
		for (let i = 0; i < text.length; i++) {
			bytes[i] = text.charCodeAt(i);
		}
		const decoder = new TextDecoder('utf-8');
		return decoder.decode(bytes);
	}
	

	private escapeForHtmlAttribute(html: string) {
		// Quick check to avoid unnecessary processing
		if (!/[&<>"'\s]/.test(html)) {
			return html;
		}
		return html
			.replace(/[&<>"'\s]/g, function(match) {
				switch (match) {
					case '&': return "&amp;";
					case '<': return "&lt;";
					case '>': return "&gt;";
					case '"': return "&quot;";
					case "'": return "&#39;";
					case ' ': return "&nbsp;"; // Including space handling
					default: return match; // Default case should not be hit due to the regex
				}
			});
	}
	

	private isIconChar(c: string) {
		if (c.length === 0) return false;

		const code = c.codePointAt(0);

		if (!code) return false;
		return (
			(code >= 0x2600 && code <= 0x26FF) ||  // Miscellaneous Symbols
			(code >= 0x2700 && code <= 0x27BF) ||  // Dingbats
			(code >= 0x1F600 && code <= 0x1F64F) ||  // Emoticons (Emoji)
			(code >= 0x1F300 && code <= 0x1F5FF) ||  // Miscellaneous Symbols and Pictographs
			(code >= 0x1F680 && code <= 0x1F6FF) ||  // Transport and Map Symbols
			(code >= 0x1F780 && code <= 0x1F7FF) ||  // Geometric Shapes Extended
			(code >= 0x25A0 && code <= 0x25FF) ||  // Geometric Shapes
			(code >= 0x2190 && code <= 0x21FF) ||  // Arrows
			/* additional icons */
			(code >= 0x2200 && code <= 0x22FF) ||  // Mathematical Operators
			(code >= 0x2300 && code <= 0x23FF) ||  // Miscellaneous Technical
			(code >= 0x2460 && code <= 0x24FF) ||  // Enclosed Alphanumerics
			(code >= 0x2500 && code <= 0x257F) ||  // Box Drawing
			(code >= 0x2580 && code <= 0x259F) ||  // Block Elements
			(code >= 0x27F0 && code <= 0x27FF) ||  // Supplemental Arrows-A
			(code >= 0x2900 && code <= 0x297F) ||  // Supplemental Arrows-B
			(code >= 0x1F800 && code <= 0x1F8FF) ||  // Supplemental Arrows-C
			(code >= 0x1F900 && code <= 0x1F9FF) ||  // Supplemental Pictographs
			(code >= 0x1F650 && code <= 0x1F67F) ||  // Emoticons Extended
			(code >= 0x1F650 && code <= 0x1F67F) ||  // Ornamental Dingbats (Note: This is the same as Emoticons Extended)
			(code >= 0x10190 && code <= 0x101CF) ||  // Ancient Symbols
			(code >= 0x1F000 && code <= 0x1F02F) ||  // Mahjong Tiles
			(code >= 0x1F030 && code <= 0x1F09F) ||  // Domino Tiles
			(code >= 0x1F0A0 && code <= 0x1F0FF)     // Playing Cards
		);
	}

	public buildDecoratorUnicode() {
		// this.functionDefinitions.map(ele => { return ele.decorator })
		const uniqueChars = new Set();
		for (let str of this.functionDefinitions.map(ele => { return ele.decorator })) {
			for (let char of str) {
				if (this.isIconChar(char))
					uniqueChars.add(char);
			}
		}
		// return [...uniqueChars].join("")
		this.decoratorUnicode = [...uniqueChars].join("")
	}

	// TODO: finish this function
	// NOTE: if too computationally expensive for large codebases over long sessions, consider marking Callstacks/Graphs as out of sync and thus rebuild cache later (or just remove them from cache to be rebuilt upon next load)... would need to remove scope caches as well
	public updateCache() {
		// updates HTML callstacks + graph caches (typically for updated decorators)

	}

	// TODO: update to only build upon viewing a function + cache... will have to clear cache when decorator changes (i.e.: when marking/unmarking reviewed || when decorator is updated)
	public async buildCallstacks(): Promise<boolean> {
		this.buildDecoratorUnicode()
		if (this._view)
			this._view.webview.postMessage({ command: "setDecoratorUnicode", decorator: this.decoratorUnicode });

		// Convert the array to a Map for faster lookups
		// this.callstacksHtml = this.callstacks?.map(callstack => {
		// 	let functionChainWithLines: string[] = []

		// 	let html = ""
		// 	html += callstack.map(ele => {
		// 		let f_calledIn = ""
		// 		if (Array.isArray(ele)) {
		// 			// if callstack is an array of arrays [[f_calledIn, calledAt], [f_calledIn2, calledAt2], ...]
		// 			// e.g.: built from CodeQL
		// 			f_calledIn = ele[0]
		// 			let calledAt = ele[1]
		// 		} else {
		// 			// callstack is just a callstack of f_calledIn [f_calledIn, f_calledIn2, ...]
		// 			// e.g.: built from custom Slither detector
		// 			f_calledIn = ele
		// 		}

		// 		let lookup_func = this.functionDefinitionsMap.get(f_calledIn);
		// 		if (lookup_func) {
		// 			if (lookup_func.startLine && lookup_func.endLine) {
		// 				// functionChainWithLines.push(`${lookup_func.filepath.split("#")[0]}#${lookup_func.startLine}-${lookup_func.endLine}`)
		// 				let hashIndex = lookup_func.filepath.indexOf("#");
		// 				let filepath = hashIndex !== -1 ? lookup_func.filepath.substring(0, hashIndex) : lookup_func.filepath;
		// 				functionChainWithLines.push(`${filepath}#${lookup_func.startLine}-${lookup_func.endLine}`);
		// 			}
		// 			return this.getFunctionDescriptiveStr(lookup_func, true)
		// 		} else {
		// 			let f_calledIn_parts = f_calledIn.split(",");
		// 			let f_calledIn_link = f_calledIn_parts.slice(-1)[0];
		// 			let f_calledIn_text = f_calledIn_parts.slice(0, -1).join(",");
		// 			return `<a href='file://${f_calledIn_link}'>${f_calledIn_text}</a> | ?`
		// 		}
		// 	}).join(" > ")
		// 	html += "</li>"

		// 	html = `<li class='callstack'><span class='export-callstack' func_chain='${functionChainWithLines.join(',')}'>🏳️‍🌈</span> ${html}`;
		// 	// let x = `<li class='callstack'>${callstack.map(f => { return  })}</li>`

		// 	return html
		// })

		return true
	}

	private getRelatedCallstacks(f: FunctionResult): number[] {
		if (this.relatedCallstacksHash[f.id]) {
			return this.relatedCallstacksHash[f.id]
		}

		let known_callstacks: number[] = []
		if (f.entrypoint_callstacks) known_callstacks = known_callstacks.concat(f.entrypoint_callstacks)
		if (f.exit_callstacks) known_callstacks = known_callstacks.concat(f.exit_callstacks)
		if (f.other_callstacks) known_callstacks = known_callstacks.concat(f.other_callstacks)

		let related_callstacks_ixs: number[] = []
		this.callstacks?.forEach((callstack, i) => {
			// skip if we know of these callstacks
			// compare HTML because may have duplicate callstacks with different indexes (e.x.: how Solidity data is gathered across multiple detectors)
			// if (this.getCallstacksHTML(known_callstacks).includes(this.getCallstacksHTML([i]))) {
			if (known_callstacks.includes(i)) {
				return
			}

			for (let ele of callstack) {
				let func_id = this.getFunctionId(ele)
				let func_name = func_id.split(",")[0]

				// continue evaluating callstack for other interesting functions
				if (this.settings?.excludedRelatedCallstacks.includes(func_name)) {	
					continue
				}
				
				if (func_id.startsWith(`${f.functionName},`)) {
					related_callstacks_ixs.push(i)
					return
				}
			}

		})

		this.relatedCallstacksHash[f.id] = related_callstacks_ixs
		return related_callstacks_ixs
	}

	private getInheritanceGraph(scope_id: string) {
		if (scope_id === 'all')
			return this.inheritanceGraph

		// get this.inheritanceGraph and filter by scope_id.split(",")[0] (scope name)
		let scope_name = scope_id.split(",")[0]
		let graph: CallGraph = { nodes: [], edges: [] }
		// get all edges first, collect list of nodes from edges, only keep seen nodes
		let seen_nodes: string[] = [scope_name]
		let nodes_before, nodes_after
		do {
			nodes_before = seen_nodes.length
			for (let e of this.inheritanceGraph.edges) {
				if (seen_nodes.includes(e.data.source) && !seen_nodes.includes(e.data.target)) {
					seen_nodes.push(e.data.target)
				}
				if (seen_nodes.includes(e.data.target) && !seen_nodes.includes(e.data.source)) {
					seen_nodes.push(e.data.source)
				}
			}
			nodes_after = seen_nodes.length
		} while (nodes_before != nodes_after)

		let new_nodes = this.inheritanceGraph.nodes.filter(n => { return seen_nodes.includes(n.data.id) })
		let new_edges = this.inheritanceGraph.edges.filter(e => { return seen_nodes.includes(e.data.source) || seen_nodes.includes(e.data.target) })
		
		return {
			nodes: new_nodes,
			edges: new_edges
		}
	}


	private async getScopeGraph(scope_id: string, return_scopes_only: boolean = false, include_inherited_functions: boolean = true, include_related_function_callstacks: boolean = false) {
		let cache__key = scope_id ===  'all~' ? 'all~' : Array.from(arguments).reduce((acc, arg) => { return acc + "~" + arg })
		
		if (true || !this.scopeGraphs[cache__key]) {
			let scope = this.scopeSummaries.find(s => { return s.id === scope_id })
			let inherited_scopes_recursive = this.scopeDefinitionsMap[scope_id]?.scope_summary?.inherits_recursive?.concat(scope_id) || [scope_id]

			// consider filtering 'all' by `f.decorator.includes('🎯')` to reduce processing and make graph smaller
			let functions_to_chart: FunctionResult[] = scope_id.startsWith('all~') ? this.functionDefinitions
																						.filter(f => { return (!('is_inherited' in f) || 'is_inherited' in f  && f.is_inherited === false) }) : this.functionDefinitions
																						.filter(f => {
																							if (include_inherited_functions) {
																								// get all recursive inherited scopes
																								return inherited_scopes_recursive.includes(f.scope_id) // get all functions in scope    // & !is_shadowed
																							} else {
																								// include functions if `is_inherited` is not defined, assume it is not inherited
																								return f.scope_id === scope_id && (!('is_inherited' in f) || 'is_inherited' in f  && f.is_inherited === false)
																							}
																						}) || []
														

		    // showing scope relationships graph
			if (scope_id.startsWith("all~") && return_scopes_only && this.callstacks) {		
				let included_function_ids: BooleanHashmap = {}
				functions_to_chart.forEach(f => { included_function_ids[f.id] = true })

				let graph: CallGraph = { nodes: [], edges: [] }

				
				/**
				 * Splits an array into roughly-equal chunks.
				 */
				function chunkArray<T>(arr: T[], chunkCount: number): T[][] {
					const size = Math.ceil(arr.length / chunkCount);
					const chunks: T[][] = [];
					for (let i = 0; i < arr.length; i += size) {
					chunks.push(arr.slice(i, i + size));
					}
					return chunks;
				}
				
				/**
				 * Builds a merged call-graph by distributing work across worker_threads.
				 */
				let extensionUri = this._context.extensionUri
				async function buildScopeGraph(
					callstacks: string[][],
					functionDefinitionsMap: Map<string, FunctionResult>,
					scopeDefinitionsMap: Record<string, ScopeDefinition>,
					includedFunctionIds: Record<string, boolean>
				): Promise<CallGraph> {
					const cpuCount = os.cpus().length;
					const chunks = chunkArray(callstacks, cpuCount);
				
					// Spawn a worker for each chunk
					const workerPromises: Promise<WorkerResult>[] = chunks.map(chunk => {
					return new Promise<WorkerResult>((resolve, reject) => {
						vscode.Uri.joinPath(extensionUri , 'media', 'workers', 'processCallstacks.js')
						const w = new Worker(require.resolve('../media/workers/processCallstacks.js'), {
						workerData: { chunk, functionDefinitionsMap, scopeDefinitionsMap, includedFunctionIds }
						});
						w.once('message', (msg: WorkerResult) => resolve(msg));
						w.once('error', reject);
						w.once('exit', code => {
						if (code !== 0) reject(new Error(`Worker exited with code ${code}`));
						});
					});
					});
				
					const results = await Promise.all(workerPromises);
				
					// Merge results, deduplicating via Sets
					const finalNodes: graphNode[] = [];
					const finalEdges: graphEdge[] = [];
					const seenNodeIds = new Set<string>();
					const seenEdgeKeys = new Set<string>();
				
					for (const { nodes, edges } of results) {
					for (const n of nodes) {
						const id = n.data.id;
						if (!seenNodeIds.has(id)) {
						seenNodeIds.add(id);
						finalNodes.push(n);
						}
					}
					for (const e of edges) {
						const key = `${e.data.source}-${e.data.target}`;
						if (!seenEdgeKeys.has(key)) {
						seenEdgeKeys.add(key);
						finalEdges.push(e);
						}
					}
					}
				
					// make all nodes hyperlinked to their containing file
					finalNodes.forEach(node => {
						let filepath = node.data.id.split("#")[0].split(",").slice(-1)[0]
						node.data.title = `<a href='file://${filepath}'>${node.data.title}</a>`;
					});					

					return { nodes: finalNodes, edges: finalEdges };
				}
				
			
				
				// if (completed_callstacks++ % 1000 === 0) {
				// 	this.setWebviewHtml("<br>Loading & processing callstacks...")
				// }
				// Usage example in your class/context:
				graph = await buildScopeGraph(
					this.callstacks,
					this.functionDefinitionsMap,
					this.scopeDefinitionsMap,
					included_function_ids
					);

				this.scopeGraphs[cache__key] = graph
				return this.scopeGraphs[cache__key]
			}

			// filters for button "Callstacks Graph w/ Search Term"
			if (scope_id.startsWith("all~") && this.callstacks) {
				let search_term = scope_id.split("~")[1]
				functions_to_chart = functions_to_chart.filter(f => { 
					let regex = new RegExp(escapeRegExp(search_term), 'gi');  
					return f.functionName.includes(search_term) || this.getFileSource(f.filepath.split("#")[0], f.startLine, f.endLine).match(regex) 
				})
			}


			// TODO: try to run below in workers 

			// functions_to_chart = functions_to_chart.slice(0, 5)
			let mergeCallstacksIntoGraphParams: mergeCallstacksIntoGraphParams = {
				graph: { nodes: [], edges: [] },
				callstacksGraphParams: {
					callstacks: [],
					return_scopes_only: return_scopes_only,
					root_scope_id: scope_id,
					append_related_function_html: include_related_function_callstacks
				},
				override_color: ""
			}

			for (let f of functions_to_chart) {
				// this.mergeCallstacksIntoGraph(f.entrypoint_callstacks, graph, seen_nodes, seen_edges, return_scopes_only, f.scope_id)
				mergeCallstacksIntoGraphParams.callstacksGraphParams.callstacks = f.entrypoint_callstacks || []
				this.mergeCallstacksIntoGraph(mergeCallstacksIntoGraphParams)
				mergeCallstacksIntoGraphParams.callstacksGraphParams.callstacks = f.exit_callstacks || []
				this.mergeCallstacksIntoGraph(mergeCallstacksIntoGraphParams)
				mergeCallstacksIntoGraphParams.callstacksGraphParams.callstacks = f.other_callstacks || []
				this.mergeCallstacksIntoGraph(mergeCallstacksIntoGraphParams)
			}

			// adding related callstacks (doing after adding all nodes to graph to prevent duplicate nodes & color related nodes correctly)
			if (include_related_function_callstacks) {
				for (let f of functions_to_chart) {
					// first merge graph
					let related_callstack_indexes = this.getRelatedCallstacks(f)
					mergeCallstacksIntoGraphParams.callstacksGraphParams.callstacks = related_callstack_indexes
					mergeCallstacksIntoGraphParams.override_color = 'lightgreen'
					this.mergeCallstacksIntoGraph(mergeCallstacksIntoGraphParams)
				}

				// then highlight related functions
				for (let f of functions_to_chart) { 
					for (let node of mergeCallstacksIntoGraphParams.graph.nodes) {
						if (node.data.id.startsWith(f.functionName) && node.data.id !== f.id) {
							node.data.backgroundColor = 'greenyellow'
						}
					}
				}
			}
			let graph = mergeCallstacksIntoGraphParams.graph

			// get all functions in scope not already retrieved
			// NOTE: Consider second state param to prevent this (declutter functions that aren't in any callstacks)
			if (!return_scopes_only) {
				let mapped_functions = graph.nodes.map(node => { return node.data.id })
				let missing_functions = functions_to_chart.filter(f => { return !mapped_functions.includes(f.id) })

				let seen_parent_ids: string[] = graph.nodes.filter(n => { return 'isParent' in n.data && n.data.isParent === true }).map(n => { return n.data.id })
				for (let f of missing_functions) {
					let source_code = this.getFileSource(f.filepath.split("#")[0], f.startLine, f.endLine)
					graph.nodes.push({ classes: 'l1', data: { id: f.id, parent: f.scope_id, title: this.getFunctionDescriptiveStr(f, true, true, true), content: source_code } })
					
					// push parent if not exists
					if (!seen_parent_ids.includes(f.scope_id)) {
						// TODO: 
						// Find scopes where inherited scope is used, color inherited scope (update where `isParent: true`)
						// let isInRecursive = this.scopeSummaries.find(s => { return s.id === f.scope_id }).inherits_recursive.includes()
						// explicit overrides from imported scopeSummary (json filie) will be applied with priority
						let lookup_scope = this.scopeSummaries.find(s => { return s.id === f?.scope_id })
						let backgroundColor = ""
						if (lookup_scope?.backgroundColor && lookup_scope?.backgroundColor !== "") {
							backgroundColor = lookup_scope?.backgroundColor
						} else {
							backgroundColor = scope?.inherits_recursive?.includes(f.scope_id) ? "red" : ""
							backgroundColor = scope?.inherits_from_recursive?.includes(f.scope_id) ? "purple" : ""
							backgroundColor = scope_id === f.scope_id ? "blue" : backgroundColor
						}

						graph.nodes.push({ data: { id: f.scope_id, label: f.scope_id.split(",")[0], isParent: true, backgroundColor: backgroundColor } })
						seen_parent_ids.push(f.scope_id)
					}
				}
			}

			// append related functions links w/ strikethrough
			graph.nodes = this.updateGraphRelatedFunctionHTMLLinks(graph.nodes)

			this.scopeGraphs[cache__key] = graph
		}
		return this.scopeGraphs[cache__key]
	}



	// private mergeCallstacksIntoGraph(callstacks: number[] | undefined, graph: CallGraph, seen_nodes: string[] = [], seen_edges: string[] = [], return_scopes_only = false, root_scope_id: string = "", override_color: string = "", append_related_function_html: boolean = false) {
	private mergeCallstacksIntoGraph({graph, seen_nodes = [], seen_edges = [], callstacksGraphParams, override_color = ""}: mergeCallstacksIntoGraphParams) {
		if (callstacksGraphParams.callstacks && callstacksGraphParams.callstacks.length > 0) {
			let graph_to_merge = this.getCallstacksGraph(callstacksGraphParams)
			for (let n of graph_to_merge.nodes) {
				let id = JSON.stringify(n)
				if (!seen_nodes.includes(id)) {
					if (override_color)
						n.data.backgroundColor = n.data.backgroundColor || override_color
					graph.nodes.push(n)
					seen_nodes.push(id)
				}
			}
			for (let e of graph_to_merge.edges) {
				let id = JSON.stringify(e)
				if (!seen_edges.includes(id)) {
					graph.edges.push(e)
					seen_edges.push(id)
				}
			}
		}
	}

	public async loadFunctionsAndScopeInfo(): Promise<boolean> {
		// export async function readResults(print : boolean = false) : Promise<boolean> {
		// Verify there is a workspace folder open to run analysis on.
		if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length == 0) {
			return false;
		}

		// remove has new data file
		if (fs.existsSync(this.hasNewDataFilePath)) {
			try {
				await fsp.unlink(this.hasNewDataFilePath);
				console.log("Deleted _reload_ready.state file");
			} catch (err) {
				console.error("Error deleting _reload_ready.state file:", err);
			}
		}

		// Loop for every workspace to read results from.
		for (let i = 0; i < vscode.workspace.workspaceFolders.length; i++) {

			// Obtain our workspace results path.
			const workspacePath = vscode.workspace.workspaceFolders[i].uri.fsPath;

			// If the file exists, we read its contents into memory.
			this.helpHTML = `<span style='font-size: 150%'>Static Analysis Context tooling by <a target='_blank' href='https://alecmaly.com'>alecmaly.com</a></span><br><br>`
			const helpFilePath = path.join(workspacePath, this.DATA_PATH, 'help.html');
			if (fs.existsSync(helpFilePath)) {
				// Read our cached results
				this.helpHTML += fs.readFileSync(helpFilePath, 'utf8');

				// if (!this.helpHTML) return false;
			} 

			// If the file exists, we read its contents into memory.
			const scopeSummariesPath = path.join(workspacePath, this.DATA_PATH, 'scope_summaries_html.json');
			if (fs.existsSync(scopeSummariesPath)) {
				// Read our cached results
				this.scopeSummaries = JSON.parse(fs.readFileSync(scopeSummariesPath, 'utf8'));

				// if (!this.scopeSummaries) return false;
			}


			// settings
			const settingsFilepath = path.join(workspacePath, this.DATA_PATH, 'settings.json');
			if (fs.existsSync(settingsFilepath)) {
				let updateSettingsFile = false
				// Read our cached results
				let settings_to_import = JSON.parse(fs.readFileSync(settingsFilepath, 'utf8'))

				if (!settings_to_import.excludedRelatedCallstacks) {
					// file exists but excludedRelatedCallstacks is empty, init with defaults
					settings_to_import.excludedRelatedCallstacks = this.settings.excludedRelatedCallstacks
					updateSettingsFile = true
				}
				this.settings = settings_to_import
				if (updateSettingsFile) {
					fs.writeFileSync(settingsFilepath, JSON.stringify(this.settings))
				}
			} else {
				fs.writeFileSync(settingsFilepath, JSON.stringify(this.settings))
			}
		
			// If the file exists, we read its contents into memory.
			const resultsPath = path.join(workspacePath, this.DATA_PATH, 'functions_html.json');
			if (fs.existsSync(resultsPath)) {
				this.functionScopesMap = new Map();
				// Read our cached results
				this.functionDefinitions = JSON.parse(fs.readFileSync(resultsPath, 'utf8'))
				this.registerCodeLensProvider() // reset code lens provider

				this.hasInheritedFunctions = this.functionDefinitions.filter(f => { return f.is_inherited === true }).length > 0
				this.functionDefinitionsMap = new Map(this.functionDefinitions.filter(f => { return this.hasInheritedFunctions ? f.is_inherited === false : true }).map(item => [item.id, item]));
				this.functionSortedIndex = new Index(this.functionDefinitions)

				this.functionDefinitions.forEach(f => {
					f.scanned_decorator = f.decorator

					this.functionDefinitionByFilepath[f.filepath.split("#")[0]] = true
					// Add a new property that is the sum of numCallstacks1 and numCallstacks2
					f.callstackCount = (f.entrypoint_callstacks?.length || 0) + (f.exit_callstacks?.length || 0) + (f.other_callstacks?.length || 0)

					if (!this.settings.excludedRelatedCallstacks.includes(f.functionName)) {
						let realtedFunctions = Array.from(new Set(this.functionDefinitions
							.filter(f2 => { return f.functionName === f2.functionName })  // && (this.hasInheritedFunctions ? f.is_inherited === false : true)   // NOTE: may want to include inherited functions in related functions
							.map(f2 => { return f2.id })))
							
							
						f.relatedFunctions = realtedFunctions
					}

					let scope_summary = this.scopeSummaries.find(s => { return s.id === f.scope_id })
					if (scope_summary) {
						let inheritance_str = `(#inherits ${scope_summary?.inherits_recursive?.length || 0} in<>out ${scope_summary?.inherits_from_recursive?.length || 0})`
						f.inheritance_str = inheritance_str
					}

					this.defaultFileLineColumnOffset[`${f.filepath.split(':')[0]}`] = f.startCol || 0

					// append to function scopesmap
					if (!this.functionScopesMap.get(f.scope_id)) {
						this.functionScopesMap.set(f.scope_id, [])
					}
					this.functionScopesMap.get(f.scope_id)?.push(f)
				});

				// if (!this.functionDefinitions) return false;
			}


			const functionOverridesPath = path.join(workspacePath, this.DATA_PATH, 'function_overrides.json');
			if (fs.existsSync(functionOverridesPath)) {
				// Read our cached results
				const raw = JSON.parse(fs.readFileSync(functionOverridesPath, 'utf8'));

				this.functionOverrides = new Map(
					Object.entries(raw).map(([funcId, override]) => [
						funcId,
						{
							...(override as object), // spreading all properties, will update content types below if needed
							decorators_to_add: new Set((override as any).decorators_to_add || []),
							decorators_to_remove: new Set((override as any).decorators_to_remove || []),
						}
					])
				);

				for (let f_id of this.functionOverrides.keys()) {
					let f_override = this.functionOverrides.get(f_id)
					if (!f_override) continue;

					let real_func = this.functionDefinitionsMap.get(f_id)
					if (real_func) {
						real_func.reviewed = f_override.reviewed || false
						real_func.function_notes = f_override.function_notes || ""
						real_func.hide_incoming_callstacks = f_override.hide_incoming_callstacks || false
						real_func.hide_outgoing_callstacks = f_override.hide_outgoing_callstacks || false

						// TODO decorator merge logic - need to handle commas
						let real_func_decorators = this.parseDecoratorStrToSet(real_func.decorator)
						let final_ascii_decorators = []
						let final_unicode_decorators = []

						for (let d of f_override.decorators_to_remove) {
							if (real_func_decorators.has(d)) {
								real_func_decorators.delete(d)
							}
						}

						for (let d of [...real_func_decorators, ...f_override.decorators_to_add]) {
							d = d.trim()
							if (this.isIconChar(d)) {
								final_unicode_decorators.push(d)
							} else {
								final_ascii_decorators.push(d)
							}
						}

						real_func.decorator = [...final_unicode_decorators].join("") + (final_ascii_decorators.length !== 0 ? "[" + [...final_ascii_decorators].join(", ") + "]" : "")
					}
					
				}

				// if (!this.functionDefinitions) return false;
			} else {
				this.functionOverrides = new Map<string, FunctionOverride>();
			}

			// If the file exists, we read its contents into memory.
			const manualFunctionRelationshipPath = path.join(workspacePath, this.DATA_PATH, 'manual_function_relationship_map.json');
			this.settings.manualFunctionRelationshipPath = manualFunctionRelationshipPath
			if (fs.existsSync(manualFunctionRelationshipPath)) {
				// Read our cached results
				this.functionManualRelationship = JSON.parse(fs.readFileSync(manualFunctionRelationshipPath, 'utf8'))

				if (!this.functionManualRelationship) return false;
			}

			const scannedFilesPath = path.join(workspacePath, this.DATA_PATH, 'cache', 'seen_files.json');
			if (fs.existsSync(scannedFilesPath)) {
				// Read our cached results
				this.scannedFiles = JSON.parse(fs.readFileSync(scannedFilesPath, 'utf8'))
				this.registerFileDecoratorProvider() // reset file decorator provider
			} else {
				this.scannedFiles = {}
			}


			// load inheritance graph
			const inheritanceGraphPath = path.join(workspacePath, this.DATA_PATH, 'graphs', 'inheritance_graph.json');
			if (fs.existsSync(inheritanceGraphPath)) {
				// Read our cached results
				this.inheritanceGraph = JSON.parse(fs.readFileSync(inheritanceGraphPath, 'utf8'))

				// if (!this.inheritanceGraph) return false;
			}


			
			const searchTemplatesPath = path.join(workspacePath, this.DATA_PATH, 'search_templates.json');
			if (fs.existsSync(searchTemplatesPath)) {
				// Read our cached results
				try {
					this.searchTemplates = JSON.parse(fs.readFileSync(searchTemplatesPath, 'utf8'))
				} catch { }
				// if (!this.searchTemplates) return false;
			}

			// If the file exists, we read its contents into memory.
			const funcStateVarReadWrittenMappingPath = path.join(workspacePath, this.DATA_PATH, 'func_state_var_read_written_mapping.json');
			if (fs.existsSync(funcStateVarReadWrittenMappingPath)) {
				// Read our cached results
				try {
					this.funcStateVarReadWrittenMapping = JSON.parse(fs.readFileSync(funcStateVarReadWrittenMappingPath, 'utf8'))
				} catch { }
				// if (!this.funcStateVarReadWrittenMapping) return false;
			}



			// load callstacks
			const callstacksPath = path.join(workspacePath, this.DATA_PATH, 'callstacks.json');
			if (fs.existsSync(callstacksPath)) {
				// Read our cached results
				// this.callstacksHtml = fs.readFileSync(callstacksPath, 'utf8').split("\n").map(cs => { return `<li class='callstack'>${cs}</li>` })
				this.callstacks = JSON.parse(fs.readFileSync(callstacksPath, 'utf8'))

				// if (!this.callstacks) return false;
			}

			const callstacksEdgeColorsPath = path.join(workspacePath, this.DATA_PATH, 'func_call_edge_colors.json');
			if (fs.existsSync(callstacksEdgeColorsPath)) {
				// Read our cached results
				// this.callstacksHtml = fs.readFileSync(callstacksPath, 'utf8').split("\n").map(cs => { return `<li class='callstack'>${cs}</li>` })
				this.func_pair_edge_colors = JSON.parse(fs.readFileSync(callstacksEdgeColorsPath, 'utf8'))

				// if (!this.func_pair_edge_colors) return false;
			}


			


			// initialize scopes
			
			for (let f of this.functionDefinitions) {
				if (f.scope_id && !this.scopeDefinitionsMap[f.scope_id]) {
					let lookup_scope = this.scopeSummaries.find(s => { return s.id === f.scope_id })

					let scope_obj: ScopeDefinition = {
						id: f.scope_id,
						name: f.scope_id.split(",")[0],
						type: lookup_scope?.type || "", // would want to lookup scope type here, currently not used anywhere
						filepath: f.scope_id.split(",")[1],
						decorator: "", // built later
						numFunctions_inherited: this.functionDefinitions.filter(f2 => { return f2.scope_id === f.scope_id && f2.is_inherited === true }).length,
						numFunctions: this.functionDefinitions.filter(f2 => { return f2.scope_id === f.scope_id && f2.is_inherited === false }).length,
						
						scope_summary: lookup_scope
					}

					this.scopeDefinitionsMap[f.scope_id] = scope_obj
				}
			}

			// TODO: remove from here once dependencies are fixed
			await this.buildCallstacks()


			// build in scope graph
			// include all in scope functions, or all functions if scope is not defined for any function
			let graph: CallGraph
			try {
				graph = await this.getScopeGraph('all~', true)
			} catch (e) {
				console.error('possible worker error', e) 
				graph = { nodes: [], edges: [] } 
			}

			// append # of other similar scope names
			for (let n of graph.nodes) {
				if ('title' in n.data) {
					let num_scopes_w_same_name = graph.nodes.filter(node => { return 'title' in node.data && 'title' in n.data && node.data.title === n.data.title && node.data.id !== n.data.id }).length + 1
					n.data.new_title = `(${num_scopes_w_same_name}) ${n.data.title}`
				}
			}
			// append collected scope decorators
			for (let n of graph.nodes) {
				if ('title' in n.data)
					n.data.title = n.data.new_title + (this.scopeDefinitionsMap[n.data.id]?.decorator || '')
			}

			this.scopeGraphs['all~'] = graph
		}

		return true;
	}

	public getFileLines(filepath: string) {
		// if not in cache, read file and cache
		if (!this.sourceFilesCache[filepath] && fs.existsSync(filepath)) {
			// Read our cached results
			this.sourceFilesCache[filepath] = fs.readFileSync(filepath, 'utf8')
				.split("\n")
		}
		return this.sourceFilesCache[filepath] || []
	}
	private getFileSource(filepath: string, startLine: number | null = null, endLine: number | null = null, filter_audit_comments: boolean = true): string {
		let filtered_lines = filter_audit_comments ? this.getFileLines(filepath)?.filter(line => { return !line.includes("~@") }) : this.sourceFilesCache[filepath]
		if (!filtered_lines) { return "..." }

		if (!startLine) { startLine = 1 }
		if (!endLine) { endLine = filtered_lines.length - 1 }

		return filtered_lines.slice(startLine - 1, endLine).join("\n") // startLine - 1 since index starts at 0
	}

	public getAuditCommentsLineOffset(filepath: string, originalLineNum: number): number {
		filepath = filepath.split("#")[0].replace("file://", "")
		let lines = this.getFileLines(filepath)
		let num_comments = lines.slice(0, originalLineNum - 1).filter(line => { return line.includes("~@") }).length

		// recursive function to check if comments exist in difference between start line and new start line
		function getOffset(startLine: number, newStartLine: number, lines: string[]) {
			let num_comments = lines.slice(startLine, newStartLine).filter(line => { return line.includes("~@") }).length
			if (num_comments > 0) {
				return getOffset(newStartLine, newStartLine + num_comments, lines)
			} else {
				return newStartLine - startLine
			}
		}

		let offset = getOffset(originalLineNum, originalLineNum + num_comments, lines)
		
		return offset
	}

	private getFunctionId(ele: string) {
		let f_calledIn = ""
		if (Array.isArray(ele)) {
			// if callstack is an array of arrays [[f_calledIn, calledAt], [f_calledIn2, calledAt2], ...]
			// e.g.: built from CodeQL
			f_calledIn = ele[0]
			let calledAt = ele[1]
		} else {
			// callstack is just a callstack of f_calledIn [f_calledIn, f_calledIn2, ...]
			// e.g.: built from custom Slither detector
			f_calledIn = ele
		}

		return f_calledIn
	}

	private updateGraphRelatedFunctionHTMLLinks(nodes: (graphNode | graphGroup)[], funcs_seen: string[] = []) {
		// skip this if funcs_seen.length > 0???
		for (let node of nodes) {
			funcs_seen.push(node.data.id)
		}

		for (let node of nodes) {
			if (!('title' in node.data))
				continue

			let lookup_func: FunctionResult | undefined = this.functionDefinitionsMap.get(node.data.id)
			if (lookup_func) {
				let relatedFunctionsHTML = lookup_func?.relatedFunctions?.length > 1 ? `(${lookup_func.relatedFunctions.map((f2_id, i) => { 
									// add `title` for tooltip
									let f2 = this.functionDefinitionsMap.get(f2_id) 
									let tooltip = f2 ? this.escapeForHtmlAttribute(this.getFunctionDescriptiveStr(f2)) : f2_id
									let anchor = `<a style='color: ${f2_id === lookup_func?.id ? 'red' : ''}' href='file://${f2_id.split(",")[1]}' value='${f2_id}' title='${tooltip}'>${i}</a>` 
									anchor = funcs_seen.includes(f2_id) ? anchor : `<s>${anchor}</s>`
									return anchor
								}).join(", ")})` : ""
				node.data.relatedFunctionsHTML = relatedFunctionsHTML
			}
		}
		return nodes
	}

	private getManuallyMappedRelationships(func_id: string, { return_scopes_only = false, seen_relationships = [], root_scope_id = "", append_related_function_html = true, directional_edges_only = undefined }: getCallstacksGraphParams): CallGraph {
		let nodes: (graphNode | graphGroup)[] = []
		let edges: graphEdge[] = []

		// include manually related callstacks
		let manually_mapped_relationships = this.functionManualRelationship.filter(relationship => { return relationship.caller_id === func_id || relationship.callee_id === func_id })

		
		for (let relationship of manually_mapped_relationships) {

			if (seen_relationships.includes(JSON.stringify(relationship))) {
				continue
			}
			seen_relationships.push(JSON.stringify(relationship))

			let pushed_node = false
			let callee_lookup_func: FunctionResult | undefined = this.functionDefinitionsMap.get(relationship.callee_id)
			let caller_lookup_func: FunctionResult | undefined = this.functionDefinitionsMap.get(relationship.caller_id)

			// continue if hiding manual callstacks from either caller or callee
			if (caller_lookup_func?.hide_outgoing_callstacks || callee_lookup_func?.hide_incoming_callstacks) {
				continue
			}

			if (callee_lookup_func && callee_lookup_func.id !== func_id && (directional_edges_only === undefined || directional_edges_only.include_direction === "outgoing" || directional_edges_only.include_direction === "both" )) {
				let mergeCallstacksIntoGraphParams: mergeCallstacksIntoGraphParams = {
					graph: { nodes: nodes, edges: edges },
					seen_nodes: nodes.map(n => { return JSON.stringify(n) }),
					seen_edges: edges.map(e => { return JSON.stringify(e) }),
					callstacksGraphParams: {
						callstacks: [],
						return_scopes_only: return_scopes_only,
						seen_relationships: seen_relationships,
						root_scope_id: root_scope_id,
						append_related_function_html: append_related_function_html,
						directional_edges_only: {
							include_direction: "outgoing",
							target_function_id: relationship.callee_id
						}
					}
				}

				mergeCallstacksIntoGraphParams.callstacksGraphParams.callstacks = callee_lookup_func.entrypoint_callstacks || []
				this.mergeCallstacksIntoGraph(mergeCallstacksIntoGraphParams)

				// ??: Consider removing if makes the graph too large. 
				mergeCallstacksIntoGraphParams.callstacksGraphParams.callstacks = callee_lookup_func.exit_callstacks || []
				this.mergeCallstacksIntoGraph(mergeCallstacksIntoGraphParams)

				// does not filter
				// ??: filter other_callstacks to only include where starting @ callee node (currently includes whole graph)
				mergeCallstacksIntoGraphParams.callstacksGraphParams.callstacks = callee_lookup_func.other_callstacks || []
				this.mergeCallstacksIntoGraph(mergeCallstacksIntoGraphParams)

				// recursive lookup from this function
				mergeCallstacksIntoGraphParams.callstacksGraphParams.callstacks = [callee_lookup_func.id]
				this.mergeCallstacksIntoGraph(mergeCallstacksIntoGraphParams)

				// include related funtions?...
				// ..


				nodes = mergeCallstacksIntoGraphParams.graph.nodes
				edges = mergeCallstacksIntoGraphParams.graph.edges

				let source_code = this.getFileSource(callee_lookup_func.filepath.split("#")[0], callee_lookup_func.startLine, callee_lookup_func.endLine)
				nodes.push({ classes: 'l1', data: { id: callee_lookup_func.id, parent: callee_lookup_func.scope_id, title: this.getFunctionDescriptiveStr(callee_lookup_func, true, true, true), content: source_code } }) // .length > 1 ? `(${realtedFunctions.map((f2_id, i) => { return `<a style='color: ${f2_id === f.id ? 'red' : ''}' href='file://${f2_id.split(",")[1]}' value='${f2_id}'>${i}</a>` }).join(", ")})` : ""
				pushed_node = true
			}

			if (caller_lookup_func && caller_lookup_func.id !== func_id  && (directional_edges_only === undefined || directional_edges_only.include_direction === "incoming" || directional_edges_only.include_direction === "both" )) {
				let mergeCallstacksIntoGraphParams: mergeCallstacksIntoGraphParams = {
					graph: { nodes: nodes, edges: edges },
					seen_nodes: nodes.map(n => { return JSON.stringify(n) }),
					seen_edges: edges.map(e => { return JSON.stringify(e) }),
					callstacksGraphParams: {
						callstacks: [],
						return_scopes_only: return_scopes_only,
						seen_relationships: seen_relationships,
						root_scope_id: root_scope_id,
						append_related_function_html: append_related_function_html,
						directional_edges_only: {
							include_direction: "incoming",
							target_function_id: relationship.caller_id
						}
					}
				}

				mergeCallstacksIntoGraphParams.callstacksGraphParams.callstacks = caller_lookup_func.entrypoint_callstacks || []
				this.mergeCallstacksIntoGraph(mergeCallstacksIntoGraphParams)

				// ??: Consider removing if makes the graph too large. 
				mergeCallstacksIntoGraphParams.callstacksGraphParams.callstacks = caller_lookup_func.exit_callstacks || []
				this.mergeCallstacksIntoGraph(mergeCallstacksIntoGraphParams)

				// does not filter
				// ??: filter other_callstacks to only include where starting @ callee node (currently includes whole graph)
				mergeCallstacksIntoGraphParams.callstacksGraphParams.callstacks = caller_lookup_func.other_callstacks || []
				this.mergeCallstacksIntoGraph(mergeCallstacksIntoGraphParams)

				// recursive lookup from this function
				mergeCallstacksIntoGraphParams.callstacksGraphParams.callstacks = [caller_lookup_func.id]
				this.mergeCallstacksIntoGraph(mergeCallstacksIntoGraphParams)

				// include related funtions?...
				// ..

				nodes = mergeCallstacksIntoGraphParams.graph.nodes
				edges = mergeCallstacksIntoGraphParams.graph.edges

				let source_code = this.getFileSource(caller_lookup_func.filepath.split("#")[0], caller_lookup_func.startLine, caller_lookup_func.endLine)
				nodes.push({ classes: 'l1', data: { id: caller_lookup_func.id, parent: caller_lookup_func.scope_id, title: this.getFunctionDescriptiveStr(caller_lookup_func, true, true, true), content: source_code } }) // .length > 1 ? `(${realtedFunctions.map((f2_id, i) => { return `<a style='color: ${f2_id === f.id ? 'red' : ''}' href='file://${f2_id.split(",")[1]}' value='${f2_id}'>${i}</a>` }).join(", ")})` : ""
				pushed_node = true
			}

			if (pushed_node) {
				edges.push({ data: { source: relationship.caller_id, target: relationship.callee_id, lineColor: 'orange' } })
			}
		}

		

		return { nodes: nodes, edges: edges }
	}

	// private getCallstacksGraph(callstacks: number[], cache__key: string = "", return_scopes_only: boolean = false, root_scope_id: string = "", append_related_function_html: boolean = true): CallGraph {
	private getCallstacksGraph({ callstacks, cache__key = "", return_scopes_only = false, seen_relationships = [], root_scope_id = "", append_related_function_html = true, directional_edges_only = undefined }: getCallstacksGraphParams): CallGraph {
		if (!this.callstacks || this.callstacks.length === 0) {
			return { nodes: [], edges: [] }
		}

		// get from cache, if exists
		if (cache__key && this.callstacksGraphCache && this.callstacksGraphCache[cache__key]) {
			return this.callstacksGraphCache[cache__key]
		}

		let root_scope: ScopeSummary | undefined = this.scopeSummaries.find(s => { return s.id === root_scope_id })

		let scopes_seen: string[] = [];
		let funcs_seen: string[] = [];

		let nodes: (graphGroup | graphNode)[] = [];
		let edges: graphEdge[] = [];

		if (directional_edges_only === undefined || directional_edges_only?.include_direction) {
			// has directional lookup
			callstackLoop: for (let i of callstacks) {
				let last_scope_id_seen

				let callstack: string[] = []
				if (typeof(i) === "number") {
					callstack = this.callstacks[i].map(ele => { return this.getFunctionId(ele) })
				} else if (typeof(i) === "string") {
					// if first element is a string (func id), assume it's an array of func ids
					callstack = [i]
				}

				let getCallstackSubset = (callstack: string[]) => {
					let startIndex = 0, endIndex = callstack.length;
				
					// Loop through callstack only once
					callstack.some((func_id, index) => {
					const f: FunctionResult | undefined = this.functionDefinitionsMap.get(func_id)
				
					if (f && f.hide_incoming_callstacks) startIndex = index;
					if (f && f.hide_outgoing_callstacks) {
						endIndex = index + 1;
						return true; // Break loop once endIndex is found
					}
					});
				
					return callstack.slice(startIndex, endIndex);
				}

				callstack = getCallstackSubset(callstack)
				
				

				// looking up / looking down functions from target function
				if (directional_edges_only !== undefined && directional_edges_only.include_direction !== "both") {
					if (directional_edges_only.include_direction === "incoming") {
						let from_index = callstack.findLastIndex(func_id => { return func_id === directional_edges_only.target_function_id })
						callstack = callstack.slice(0, from_index + 1)
					} else if(directional_edges_only.include_direction === "outgoing") {
						let from_index = callstack.findIndex(func_id => { return func_id === directional_edges_only.target_function_id })
						callstack = callstack.slice(from_index)
					}
				}

				functionLoop: for (let [j, func_id] of callstack.entries()) {
					if (j > 0) {
						// push relationship edge
						if (!return_scopes_only) {
							let caller = callstack[j - 1]
							let callee = callstack[j]
							let lineColor = this.func_pair_edge_colors[`${caller}~${callee}`] || ""
							edges.push({ data: { source: callstack[j - 1], target: callstack[j], lineColor: lineColor } })
						// edges.push({ data: { source: this.getFunctionId(this.callstacks[i][j - 1]), target: this.getFunctionId(this.callstacks[i][j]) } })
						}
					}

					// if func has been seen before, it's node has been added
					if (funcs_seen.includes(func_id))
						continue
					funcs_seen.push(func_id)
					

					
					
					let lookup_func: FunctionResult | undefined = this.functionDefinitionsMap.get(func_id)	
					if (lookup_func) {
						if (return_scopes_only) {
							nodes.push({ classes: 'l1', data: { id: lookup_func.scope_id, title: lookup_func.scope_id.split(",")[0], content: lookup_func.scope_id } })
							scopes_seen.push(lookup_func.scope_id)

							if (last_scope_id_seen && lookup_func.scope_id)
								edges.push({ data: { source: last_scope_id_seen, target: lookup_func.scope_id } })

							// collect decorators from all functions for scope
							if (lookup_func.scope_id) {
								for (let c of [...lookup_func.decorator]) {
									if (!this.isIconChar(c))
										continue


									if (lookup_func.scope_id && !this.scopeDefinitionsMap[lookup_func.scope_id]?.decorator) {
										this.scopeDefinitionsMap[lookup_func.scope_id].decorator = c
									} else if (lookup_func.scope_id && !this.scopeDefinitionsMap[lookup_func.scope_id].decorator.includes(c)) {
										this.scopeDefinitionsMap[lookup_func.scope_id].decorator += c
									}
								}
							}

							last_scope_id_seen = lookup_func.scope_id
							continue
						}

						// get source code from cache or read file
						// readfile
						let source_code = this.getFileSource(lookup_func.filepath.split("#")[0], lookup_func.startLine, lookup_func.endLine)
						nodes.push({ classes: 'l1', data: { id: lookup_func.id, parent: lookup_func.scope_id, title: this.getFunctionDescriptiveStr(lookup_func, true, true, true), content: source_code } }) // .length > 1 ? `(${realtedFunctions.map((f2_id, i) => { return `<a style='color: ${f2_id === f.id ? 'red' : ''}' href='file://${f2_id.split(",")[1]}' value='${f2_id}'>${i}</a>` }).join(", ")})` : ""

						// push scope if not seen before
						if (lookup_func.scope_id && !scopes_seen.includes(lookup_func.scope_id)) {
							let lookup_scope = this.scopeSummaries.find(s => { return s.id === lookup_func?.scope_id })
							let backgroundColor = ""
							if (lookup_scope?.backgroundColor && lookup_scope?.backgroundColor !== "") {
								backgroundColor = lookup_scope?.backgroundColor
							} else {
								backgroundColor = root_scope?.inherits_recursive?.includes(lookup_func.scope_id) ? "red" : ""
								backgroundColor = root_scope?.inherits_from_recursive?.includes(lookup_func.scope_id) ? "purple" : backgroundColor
								backgroundColor = root_scope_id === lookup_func.scope_id ? "blue" : backgroundColor
							}
							
							nodes.push({ data: { id: lookup_func.scope_id, label: lookup_func.scope_id.split(",")[0], isParent: true, backgroundColor: backgroundColor } })    // perhaps change label to func.scope_id.split(",")[0]  ?
							scopes_seen.push(lookup_func.scope_id)
						}

						// return this.getFunctionDescriptiveStr(lookup_func, true);

						// TODO: idea for incoming, update nodes to nodes_to_add, reset if hide_incoming_callstacks = true, set at end of loop
						// don't show reminaing functions
						// TODO: fix, broken, will not show related call stacks up the chain
						// if (lookup_func.hide_outgoing_callstacks) {
						// 	// return { nodes: nodes, edges: edges }
						// 	break callstackLoop   /// broken?
						// }
					}
					else {
						if (!return_scopes_only) {
							// if func not found, add as node with link to file - source code not available??
							let scope_id = func_id.split("#")[0].split(",").slice(-1)[0] // get scope id from func_id
							nodes.push({ classes: 'l1', data: { id: func_id, parent: scope_id, title: `<a href='file://${func_id.split(",").slice(-1)[0]}'>${func_id.split(",").slice(0, -1).join(",")}</a> | ?` } })

							// don't have details, default scope as the file
							if (!scopes_seen.includes(scope_id)) {
								scopes_seen.push(scope_id)
								let scope_name = func_id.split("#")[0].split("/").slice(-1)[0] // get last part of path, should be name of file
								nodes.push({ data: { id: scope_id, label: scope_name, isParent: true, backgroundColor: "" } })   
							}
						
						}
					}

					

					// TODO: FIX INCLUDE MANUALLY MAPPED
					// this.getManuallyMappedRelationships(func_id, seen_relationships)
					let params: getCallstacksGraphParams = {
						callstacks: [],  	// not used
						cache__key: "",		// not used
						return_scopes_only: return_scopes_only,
						seen_relationships: seen_relationships,
						root_scope_id: root_scope_id,
						append_related_function_html: append_related_function_html,
						directional_edges_only: directional_edges_only
					}
					let manualMappedRelationshipsGraph: CallGraph = this.getManuallyMappedRelationships(func_id, params)
					for (let node of manualMappedRelationshipsGraph.nodes) {
						let id = node.data.id // JSON.stringify(node)
						if (!funcs_seen.includes(id)) {
							nodes.push(node)
							funcs_seen.push(id)
						}
					}
					for (let edge of manualMappedRelationshipsGraph.edges) {
						edges.push(edge)
					}
				}
			}
		} else {
			// only return function as node
			let lookup_func: FunctionResult | undefined = this.functionDefinitionsMap.get(directional_edges_only?.target_function_id || "")
			if (lookup_func) {
				let source_code = this.getFileSource(lookup_func.filepath.split("#")[0], lookup_func.startLine, lookup_func.endLine)
					nodes.push({ classes: 'l1', data: { id: lookup_func.id, parent: lookup_func.scope_id, title: this.getFunctionDescriptiveStr(lookup_func, true, true, true), content: source_code } }) 
			}	
		}


		if (append_related_function_html) {
			// append related functions links w/ strikethrough
			nodes = this.updateGraphRelatedFunctionHTMLLinks(nodes, funcs_seen)
		}


		let graph: CallGraph = { nodes: nodes, edges: edges }
		if (cache__key && this.callstacksGraphCache) {
			this.callstacksGraphCache[cache__key] = graph
		}

		
		

		return graph;
	}

	// TODO: update this function to build HTML callstacks on the spot
	private getCallstacksHTML(callstacks: number[]) {
		if (!this.callstacksHtml) {
			return ""
		}

		let html = ""
		for (let index of callstacks) {
			html += this.callstacksHtml[index] + "<br>"
		}

		return html
	}


	private hasNonEmptyValue(obj: any, prop: string): boolean {
		const value = obj[prop];

		// Check for null, undefined, or empty string
		if (!value || (typeof value === 'string' && value.trim() === '')) {
			return false;
		}

		// Check for empty array
		if (Array.isArray(value) && value.length === 0) {
			return false;
		}

		// Check for empty object
		if (typeof value === 'object' && !Object.keys(value).length) {
			return false;
		}

		return true;
	}

	private getFunctionDescriptiveStr(f: FunctionResult, hyperlinedHTML: boolean = false, include_manual_relationship_link: boolean = false, function_params_newline: boolean = false) {
		if (hyperlinedHTML) {
			// graph
			let manual_relationship_link = `<span class='manual-relationship-link' style='cursor: pointer' value='${f.id}'>🪢</span>`
			let search_link = `<span style='cursor: pointer' search_regex='\\.${f.functionName}'>🔍</span>`
			let html_link = `<a href='#${f.id}' data-scope="${f.scope_id}">🔗</a>`
			let tooltip = this.escapeForHtmlAttribute(this.getFunctionDescriptiveStr(f))
			let f_str = `(${f.endLine - f.startLine - 1}) ${f.reviewed ? '[X] ' : ''}${include_manual_relationship_link ? `${manual_relationship_link} ` : ""}${search_link} ${html_link} <a href='file://${f.filepath}' title=${tooltip}>${f.qualifiedName_full || f.qualifiedName || f.functionName}</a>${!function_params_newline && f.functionParameters ? f.functionParameters : ""}${!function_params_newline && f.functionReturns ? " -> " + f.functionReturns : ""} |${f.decorator ? ` ${f.decorator} ` : ""}${function_params_newline && f.functionParameters ? "<br>" + f.functionParameters : ""}${function_params_newline && f.functionReturns ? "<br> -> " + f.functionReturns : ""}`

			return f_str
		}


		// search functions
		let relativePath = f.filepath
		if (vscode.workspace.workspaceFolders) {
			for (let workspacePath of vscode.workspace.workspaceFolders) {
				let regex = new RegExp(escapeRegExp('^' + workspacePath.uri.fsPath));  // '^' matches the beginning of the string
				relativePath = relativePath.replace(regex, ".")
			}
		}
		return `${f.reviewed ? '[X] ' : ''}${f.qualifiedName || f.functionName}${!function_params_newline && f.functionParameters ? f.functionParameters : ""}${!function_params_newline && f.functionReturns ? " -> " + f.functionReturns : ""} | (Taints: ${f.tainted_locations_count || "?"}) (SLOC: ${f.endLine - f.startLine || '?'}) (# callstacks: ${f.callstackCount}) ${f.decorator},...${f.inheritance_str}...${relativePath}${function_params_newline && f.functionParameters ? "<br>" + f.functionParameters : ""}${function_params_newline && f.functionReturns ? "<br> -> " + f.functionReturns : ""}`
	}

	private runningRipgrepCommand: boolean = false;
	private async runRipgrepCommand(search_regex: string): Promise<string> {
		if (this.runningRipgrepCommand) {
			vscode.window.showWarningMessage("Ripgrep command is already running. Please wait for it to finish.");
			return "";
		}
		this.runningRipgrepCommand = true;
		
		try {
			// Check if ripgrep is available
			try {
				await new Promise<void>((resolve, reject) => {
					const testRg = spawn("rg", ["--version"], { stdio: 'ignore' });
					const timeout = setTimeout(() => {
						testRg.kill();
						reject(new Error("ripgrep test timeout"));
					}, 3000);

					testRg.on("close", (code) => {
						clearTimeout(timeout);
						if (code === 0) {
							resolve();
						} else {
							reject(new Error("ripgrep not available"));
						}
					});
					testRg.on("error", (err) => {
						clearTimeout(timeout);
						reject(new Error("ripgrep not found"));
					});
				});
			} catch (error) {
				vscode.window.showWarningMessage("Ripgrep (rg) is not installed or not in PATH. Please install ripgrep for faster search functionality.");
				return "";
			}

			return await new Promise<string>((resolve, reject) => {
				const rgArgs = [
					"-S", // smart case, case sensitive if uppercase present, else insensitive
					"--no-heading",
					"--with-filename",
					"--line-number",
					"--column",
					"--color", "never"
				];
				if (this.settings.ctnt_uses_gitignore === false) {
					rgArgs.push("--no-ignore");
				}
				rgArgs.push("--", search_regex);


				const rg = spawn("rg", rgArgs, { 
					cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || process.cwd(),
					stdio: ['ignore', 'pipe', 'pipe']

				});

				
				let stderr = "";
				let isResolved = false;
				const chunks: Buffer[] = [];


				const timeout = setTimeout(() => {
					if (!isResolved) {
						rg.kill();
						reject(new Error("ripgrep command timeout"));
					}
				}, 30000); // 30 second timeout


				const start = Date.now();
				logger.appendLine(`Running ripgrep command: rg ${rgArgs.join(" ")}`);

				rg.stdout?.on("data", (data: Buffer) => {
					chunks.push(data);
				});

				rg.stderr?.on("data", (data: Buffer) => {
					stderr += data.toString('utf8');
				});

				rg.on("close", (code) => {
					clearTimeout(timeout);
					if (!isResolved) {
						isResolved = true;
						if (code === 0 || code === 1) { // code 1 means no matches found, which is valid
							const duration = (Date.now() - start) / 1000;
							let out = Buffer.concat(chunks).toString('utf8');
							logger.appendLine(`ripgrep finished in ${duration} seconds`);
							resolve(out);
						} else {
							reject(new Error(`ripgrep failed with code ${code}: ${stderr}`));
						}
					}
				});

				rg.on("error", (err) => {
					clearTimeout(timeout);
					if (!isResolved) {
						isResolved = true;
						reject(new Error(`Failed to start ripgrep: ${err.message}`));
					}
				});
			});
		} catch (error) {
			vscode.window.showErrorMessage(`Ripgrep command failed: ${error}`);
			return "";
		} finally {
			this.runningRipgrepCommand = false;
		}
	}

	private async filterFunctionDefinitions(functions: FunctionResult[], regexPattern: string = "", excludeRegexPattern: string = "", cntRegexPattern: string = "", mode: FunctionFilterMode = FunctionFilterMode.Identifier): Promise<FunctionResult[]> {
		// max lines in file must be < 1000000000
		const max_filesize = 6
		excludeRegexPattern = excludeRegexPattern.trim()
		cntRegexPattern = cntRegexPattern.trim()

		if (mode === FunctionFilterMode.Content) {
			if (!cntRegexPattern) {
				return []
			}
			// search with grep
			// cntRegexPattern is the grep pattern
			// regexPattern is the match for filenames/paths
			// excludeRegexPattern is the exclude pattern for filenames/paths
			
			let matches = (await this.runRipgrepCommand(cntRegexPattern)).split("\n").filter(line => line.trim() !== "");
			
			let retFuncs: Set<FunctionResult> = new Set<FunctionResult>();
			let retLocMap = new Map<string, Loc[]>();
			let basePath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || ""
			let seen_scopes = new Set<string>();
			matches.forEach(line => {
				let filename = line.split(":")[0]
				let lineNum = parseInt(line.split(":")[1])
				let colNum = parseInt(line.split(":")[2]) 
				let content = line.split(":").slice(3).join(":")
				let filepath = path.join(basePath, filename)

				if (regexPattern) {
					const regex = new RegExp(escapeRegExp(regexPattern), 'i');
					if (!regex.test(filepath)) { return }
				}

				if (excludeRegexPattern) {
					// should we update to keep explicit includes?
					const excludeRegex = new RegExp(escapeRegExp(excludeRegexPattern), 'i');
					if (excludeRegex.test(filepath)) { return }
				}


				let func = this.functionSortedIndex.getByLine(filepath, lineNum)

				if (func) {
					retFuncs.add(func)
					
					if (!seen_scopes.has(func.scope_id)) {
						// already seen this scope, do not add again
						seen_scopes.add(func.scope_id)

						// add related functions
						let relatedFunctions = this.functionScopesMap.get(func.scope_id) || []
						relatedFunctions.forEach(f => {
							retFuncs.add(f)
						})
					}
				}

				if (!retLocMap.has(func?.id || "none")) {
					retLocMap.set(func?.id || "none", [])
				}

				retLocMap.get(func?.id || "none")?.push({
					filepath: filepath,
					lineNum: lineNum,
					colNum: colNum,
					content: content.slice(0, 300), // MAX_LOC_CHARS = 300.. limit network traffic size
				})
			})
			
			// make retFuncs a copy/clone to not add locs to the original functions
			retFuncs = new Set(Array
							.from(retFuncs).map(f => { return { ...f } })
							.sort((f, f2) => {
								// Sort by scope_id, then filename (filepath), then by startLine, then by endLine, then by functionName
								const scopeCompare = f.scope_id.localeCompare(f2.scope_id);
								if (scopeCompare !== 0) return scopeCompare;
								const fileCompare = f.filepath.localeCompare(f2.filepath);
								if (fileCompare !== 0) return fileCompare;
								if (f.startLine !== f2.startLine) return f.startLine - f2.startLine;
								if (f.endLine !== f2.endLine) return f.endLine - f2.endLine;
								return f.functionName.localeCompare(f2.functionName);
							})
						)
			
			// add none function, set every field to defaults
			if (retLocMap.has("none")) {
				let locs = retLocMap.get("none") || []
				let noneFunc: FunctionResult = {
					id: "none",
					scope_id: "",
					functionName: "",
					functionParameters: "",
					functionReturns: "",
					startLine: 0,
					endLine: 0,
					startCol: 0,
					filepath: "",
					filepath_body: "",
					qualifiedName_full: "",
					qualifiedName: "",
					filename: "",
					scanned_decorator: "",
					decorator: "",
					state_var_summary: "",
					entrypoint_callstacks: [],
					exit_callstacks: [],
					other_callstacks: [],
					entrypoint_callstacks_html: "",
					exit_callstacks_html: "",
					other_callstacks_html: "",
					related_callstacks_html: "",
					entrypoint_callstacks_graph: { nodes: [], edges: [] },
					exit_callstacks_graph: { nodes: [], edges: [] },
					other_callstacks_graph: { nodes: [], edges: [] },
					callstacks_graph: { nodes: [], edges: [] },
					related_callstacks_graph: { nodes: [], edges: [] },
					function_summary_html: "",
					tainted_locations_count: 0,
					tainted_locations_html: "",
					reviewed: false,
					hide_incoming_callstacks: false,
					hide_outgoing_callstacks: false,
					function_notes: "",
					checkbox_ids_to_check: [],
					checkbox_ids_to_color: [],
					related_functions_html: "",
					callstackCount: 0,
					relatedFunctions: [],
					inheritance_str: "",
					additional_info_html: "",
					called_at: []
				}
				retFuncs.add(noneFunc)
			}
			
			// add locs to funcs
			for (let f of retFuncs) {
				if (retLocMap.has(f.id)) {
					// limiting 200 on client side (MAX_LOCS_DISPLAY). Limit here to reduce network traffic size
					f.locs = retLocMap.get(f.id)?.slice(0, 201) || []
				} else {
					f.locs = []
				}
			}

			logger.appendLine(`returning at time: ${new Date().toLocaleTimeString()} with ${retFuncs.size} functions matched`)
			return Array.from(retFuncs)
			// let base = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || "";
			// let grepResults = this.runRipgrepCommand(`grep -r -n -E ${cntRegexPattern} ${base}`, base);

			// convert grep results to FunctionResult[]
		}

		return functions
			// .filter(f => { return !f.hasOwnProperty('is_inherited') || f.is_inherited === false }) // do not show inherited functions
			.filter(f => {
				// do not show inherited functions, these will be shown on their base [class]
				if (f.hasOwnProperty('is_inherited') && f.is_inherited === true)
					return false

				const regex = new RegExp(escapeRegExp(regexPattern), 'gi');
				const excludeRegex = new RegExp(escapeRegExp(excludeRegexPattern), 'gi');

				// if (mode === FunctionFilterMode.Content) {					
				// 	let source = this.getFileSource(f.filepath.split("#")[0], f.startLine, f.endLine, true)
				// 	if (excludeRegexPattern) {
				// 		if (excludeRegex.test(source)) {
				// 			return false
				// 		}
				// 	}
				// 	return regex.test(source)
				// }

				const hasInterestingContent = this.settings.showAllFunctions || this.hasNonEmptyValue(f, 'decorator') || this.hasNonEmptyValue(f, 'entrypoint_callstacks') || this.hasNonEmptyValue(f, 'exit_callstacks') || this.hasNonEmptyValue(f, 'other_callstacks') || this.hasNonEmptyValue(f, 'state_vars_read') || this.hasNonEmptyValue(f, 'state_vars_written')

				// hide based on reviewed state
				if (this.currentFilteredFunctionState.hideReviewedState === "In Scope Only" && !f.decorator.includes("🎯")) {
					return false
				}
				
				if (this.currentFilteredFunctionState.hideReviewedState === "Hide Reviewed Except In Scope" && f.reviewed && !f.decorator.includes("🎯")) {
					return false
				}

				if (this.currentFilteredFunctionState.hideReviewedState === "Hide Reviewed" && f.reviewed) {
					return false
				}

				let functionDescripiveStr = this.getFunctionDescriptiveStr(f).replace("[X] ", '')

				if (excludeRegexPattern)
					return regex.test(functionDescripiveStr) && !excludeRegex.test(functionDescripiveStr) && hasInterestingContent
				else
					return regex.test(functionDescripiveStr) && hasInterestingContent
			})
			.sort((f, f2) => {
				if (this.functionSortOption === '# Callstacks') {
					return (f2.callstackCount - f.callstackCount)
				}

				if (this.functionSortOption === 'Alpha. + # Callstacks') {
					let f_1 = f.filepath.split("#")[0] + "#" + ((f.callstackCount)).toString().padStart(max_filesize, "0")
					let f_2 = f2.filepath.split("#")[0] + "#" + ((f2.callstackCount)).toString().padStart(max_filesize, "0")

					return f_2.localeCompare(f_1)
				}

				if (this.functionSortOption === 'SLOC') {
					return (f2.endLine - f2.startLine) - (f.endLine - f.startLine)
				}

				if (this.functionSortOption === 'Alpha. + SLOC') {
					let f_1 = f.filepath.split("#")[0] + "#" + (f.endLine - f.startLine).toString().padStart(max_filesize, "0")
					let f_2 = f2.filepath.split("#")[0] + "#" + (f2.endLine - f2.startLine).toString().padStart(max_filesize, "0")

					return f_2.localeCompare(f_1)
				}

				// default sort option:   'Alpha. + Line #'
				let f_1 = f.filepath.split("#")[0] + "#" + f.startLine.toString().padStart(max_filesize, "0")
				let f_2 = f2.filepath.split("#")[0] + "#" + f2.startLine.toString().padStart(max_filesize, "0")

				return f_1.localeCompare(f_2)
			})
	}

	public showScope(scope_id: string, checkbox_ids_to_check: string[]) {
		if (this._view) {
			this._view.show?.(true); // `show` is not implemented in 1.49 but is for 1.50 insiders

			let scope = this.scopeSummaries.find(scope => { return scope.id == scope_id })
			if (!scope)
				return

			this._view.webview.postMessage({ command: "displayScope", scope: scope, checkbox_ids_to_check: checkbox_ids_to_check });
		}
	}

	public showReferences(f: FunctionResult) {
		// for (let ref of references) {
		let start_filepath = f.filepath.split("#")[0]
			// let line = parseInt(ref.split("#")[1])
			// }

		let reference_ranges = !f.called_at ? [] : f.called_at.map(ref => {
			let filepath = ref.split("#")[0].replace("file://", "")
			let line = parseInt(ref.split("#")[1]) // may want to resolve line numbers w/ parser instead of here
			return new vscode.Location(vscode.Uri.file(filepath), new vscode.Position(line + this.getAuditCommentsLineOffset(filepath, line), 0))
		})
		vscode.commands.executeCommand('editor.action.peekLocations', 
			vscode.Uri.file(start_filepath), 
			new vscode.Position(f.startLine + this.getAuditCommentsLineOffset(f.filepath, f.startLine), 0),
			reference_ranges
		);
	}

	public showFunction(f_id: string, navigated_from_history: boolean = false, mode: "Combined" | "Split" = "Combined", include_related_callstacks: boolean = false) {
		if (this._view) {
			this._view.show?.(true); // `show` is not implemented in 1.49 but is for 1.50 insiders

			let func = this.functionDefinitions.find(f => { return f.id == f_id && !f.is_inherited})
			if (!func)
				return

			let getCallstacksGraphParams: getCallstacksGraphParams = {
				callstacks: [],
				cache__key: "",
				root_scope_id: func.scope_id
			}

			if (mode === "Split") { 
				func.entrypoint_callstacks_html = ""
				if (func.entrypoint_callstacks && func.entrypoint_callstacks.length > 0) {
					// let callstacks = this.getCallstacksHTML(func.entrypoint_callstacks)
					// func.entrypoint_callstacks_html = "<h3>Entrypoint Callstacks</h3></ul>" + callstacks + "</ul>"
					func.entrypoint_callstacks_html = "<h3>Entrypoint Callstacks</h3>"
	
					getCallstacksGraphParams.callstacks = func.entrypoint_callstacks
					getCallstacksGraphParams.cache__key = `${func.id}-entrypoint`
					let callstacks_graph = this.getCallstacksGraph(getCallstacksGraphParams)
					func.entrypoint_callstacks_graph = callstacks_graph
				}
	
				func.exit_callstacks_html = ""
				if (func.exit_callstacks && func.exit_callstacks.length > 0) {
					// let callstacks = this.getCallstacksHTML(func.exit_callstacks)
					// func.exit_callstacks_html = "<h3>Exit Callstacks</h3></ul>" + callstacks + "</ul>"
					func.exit_callstacks_html = "<h3>Exit Callstacks</h3>"
	
					getCallstacksGraphParams.callstacks = func.exit_callstacks
					getCallstacksGraphParams.cache__key = `${func.id}-exit`
					let callstacks_graph = this.getCallstacksGraph(getCallstacksGraphParams)
					func.exit_callstacks_graph = callstacks_graph
				}
	
				func.other_callstacks_html = ""
				if (func.other_callstacks && func.other_callstacks.length > 0) {
					// let callstacks = this.getCallstacksHTML(func.other_callstacks)
					// func.other_callstacks_html = "<h3>Other Callstacks</h3></ul>" + callstacks + "</ul>"
					func.other_callstacks_html = "<h3>Other Callstacks</h3>"
	
					getCallstacksGraphParams.callstacks = func.other_callstacks
					getCallstacksGraphParams.cache__key = `${func.id}-other`
					let callstacks_graph = this.getCallstacksGraph(getCallstacksGraphParams)
					func.other_callstacks_graph = callstacks_graph
				}
			}


			
			// all callstacks in a single graph			
			
			// get related callstacks
			let related_callstack_indexes: number[] = this.getRelatedCallstacks(func)
			// let callstacks = this.getCallstacksHTML(related_callstack_indexes)
			// func.related_callstacks_html = "<h3>Related Callstacks</h3></ul>" + callstacks + "</ul>"
			
			// getCallstacksGraphParams.callstacks = related_callstack_indexes
			// getCallstacksGraphParams.cache__key = `${func.id}-related`
			// let callstacks_graph = this.getCallstacksGraph(getCallstacksGraphParams)
			// func.related_callstacks_graph = callstacks_graph
			// // color all related nodes
			// for (let node of func.related_callstacks_graph.nodes) {
			// 	if (node.data.id.startsWith(`${func.functionName},`) && node.data.id !== func.id) {
			// 		node.data.backgroundColor = "greenyellow"
			// 	}
			// }
			
			if (mode === "Combined") {
				let callstacks: number[] | string[] = [...new Set(func.entrypoint_callstacks.concat(func.exit_callstacks).concat(func.other_callstacks))]
				if (callstacks.length === 0) {
					// if function is not in any callstacks, just use itself as it may still have manualy mapped relationships
					callstacks = [func.id]
				}
				getCallstacksGraphParams.callstacks = callstacks
				getCallstacksGraphParams.cache__key = ""
				
				let all_callstacks_graph: CallGraph
				all_callstacks_graph = this.getCallstacksGraph(getCallstacksGraphParams)

				if (include_related_callstacks) {
					let seen_func_ids = all_callstacks_graph.nodes.map(n => { return n.data.id })

					getCallstacksGraphParams.cache__key = ""
					getCallstacksGraphParams.callstacks = related_callstack_indexes
					let mergeCallstacksIntoGraphParams: mergeCallstacksIntoGraphParams = {
						graph: all_callstacks_graph,
						seen_nodes: all_callstacks_graph.nodes.map(n => { return JSON.stringify(n) }),
						seen_edges: all_callstacks_graph.edges.map(e => { return JSON.stringify(e) }),
						callstacksGraphParams: getCallstacksGraphParams
					}
					this.mergeCallstacksIntoGraph(mergeCallstacksIntoGraphParams)
					all_callstacks_graph = mergeCallstacksIntoGraphParams.graph

					// color related nodes
					for (let node of all_callstacks_graph.nodes) {
						if (!seen_func_ids.includes(node.data.id) && node.data.id !== func.id && node.data.id.startsWith(`${func.functionName},`)) {
							node.data.backgroundColor = "greenyellow"
							continue
						}
						if (node.data.id && !seen_func_ids.includes(node.data.id)) {
							node.data.backgroundColor = "lightgreen"
							continue
						}
					}

					// getCallstacksGraphParams.callstacks = [...new Set(getCallstacksGraphParams.callstacks.concat(related_callstack_indexes))]
					// getCallstacksGraphParams.cache__key = `${func.id}-all-related`
				}

				// color selected node
				if (all_callstacks_graph.nodes) {
					let n = all_callstacks_graph.nodes.find(node => { return node.data.id === func?.id })
					if (n) n.data.backgroundColor = "yellow"
				}

				func.callstacks_graph = all_callstacks_graph
			}

			let additional_checkboxes_to_check = func.callstacks_graph.nodes.map(n => { 
				let color = n.data?.backgroundColor || (func && n.data.id !== func.id ? '' : '')
				return `${n.data.id}~~${color}` 
			})
			let checkbox_ids_to_check = [...new Set(func.checkbox_ids_to_check.concat(additional_checkboxes_to_check))]	


			// get related functions (is this too computationally expensive for apps with too many functions?, should we process on load of file?)
			let exclude_list: string[] = ['interface', 'test', 'mock']
			
			// exact matches
			let related_functions_exact_html = this.functionDefinitions
				.filter((value, index, self) => self.findIndex(f => f.id === value.id) === index)  // filter unique
				.filter(f => { return func && f !== func && f.functionName.toLowerCase() === func.functionName.toLowerCase() && exclude_list.every(exclude => !f.id.includes(exclude)); })
				.map(f => { return `(SLOC: ${f.endLine - f.startLine}) ` + this.getFunctionDescriptiveStr(f, true) + ` | ${f.id}` })
				.join("<br>")

			// non-exact matches
			let related_functions_fuzzy_html = this.functionDefinitions
				.filter((value, index, self) => self.findIndex(f => f.id === value.id) === index)  // filter unique
				.filter(f => { return func && f !== func && f.functionName.toLowerCase() !== func.functionName.toLowerCase() && f.functionName.toLowerCase().includes(func.functionName.toLowerCase()) && exclude_list.every(exclude => !f.id.includes(exclude)); })
				.map(f => { return `(SLOC: ${f.endLine - f.startLine}) ` + this.getFunctionDescriptiveStr(f, true) + ` | ${f.id}` })
				.join("<br>")

			func.related_functions_html = (related_functions_exact_html ? `<b>(exact)</b><br> ${related_functions_exact_html}` : '') + (related_functions_fuzzy_html ? `<br><b>(substring)</b><br> ${related_functions_fuzzy_html}` : '')

			this._view.webview.postMessage({ command: "displayFunction", function: func, navigated_from_history: navigated_from_history });
			this.showScope(func.scope_id, checkbox_ids_to_check)
		}
	}


	public showFilteredScopesRegex(regexPattern: string, excludeRegexPattern: string) {
		const max_filesize = 6
		excludeRegexPattern = excludeRegexPattern.trim()


		if (this._view) {
			this._view.show?.(true); // `show` is not implemented in 1.49 but is for 1.50 insiders


			let scopeIdObjs = Object.keys(this.scopeDefinitionsMap).filter(scope_id => {
				let scope = this.scopeDefinitionsMap[scope_id]
				let scope_summary = this.scopeSummaries.find(s => { return s.id === scope_id })

				const regex = new RegExp(escapeRegExp(regexPattern), 'gi');
				const excludeRegex = new RegExp(escapeRegExp(excludeRegexPattern), 'gi');

				let inheritance_str = `(#inherits ${scope_summary?.inherits_recursive?.length || 0} in<>out ${scope_summary?.inherits_from_recursive?.length || 0})`
				let scopeDescripiveStr = `(${scope.type}) ${scope.id}${scope.decorator}${inheritance_str}`  // this is what is filtered on, not what is displayed

				if (excludeRegexPattern)
					return regex.test(scopeDescripiveStr) && !excludeRegex.test(scopeDescripiveStr)
				else
					return regex.test(scopeDescripiveStr)
			})
				.sort((f, f2) => {
					// default sort option:   'Alpha. + Line #'
					let f_1 = f.split("#")[0] + "#" + f.toString().padStart(max_filesize, "0")
					let f_2 = f2.split("#")[0] + "#" + f2.toString().padStart(max_filesize, "0")

					return f_1.localeCompare(f_2)
				})
				.map(scope_id => {
					return { "id": scope_id, "scopeDefinition": this.scopeDefinitionsMap[scope_id] }
				})


			// return scopeIdObjs
			this._view.webview.postMessage({ command: "searchScopes", scopeIdObjs: scopeIdObjs || [] })
		}
	}

	public async showFilteredFunctionsRegex(regexPattern: string, excludeRegexPattern: string, cntRegexPattern: string = "", mode: FunctionFilterMode = FunctionFilterMode.Identifier) {
		if (this._view) {
			this._view.show?.(true); // `show` is not implemented in 1.49 but is for 1.50 insiders

			// get functions
			let filteredFunctions = await this.filterFunctionDefinitions(this.functionDefinitions, regexPattern, excludeRegexPattern, cntRegexPattern, mode)

			let functionIdObjs = filteredFunctions.map(f => {
					return { "id": f.id, "name": this.getFunctionDescriptiveStr(f), "scope_id": f.scope_id, "locs": f.locs || [] }
				})
			// get callstacks
			let callstacks: string[] = []
			// let seen = new Set();
			// let callstacks = this.callstacksHtml?.filter(callstack_html => {
			// 	if (seen.has(callstack_html)) return false; // Skip duplicates
			// 	seen.add(callstack_html);

			// 	const regex = new RegExp(regexPattern, 'gi');
			// 	const excludeRegex = new RegExp(excludeRegexPattern, 'gi');

			// 	if (excludeRegexPattern != "")
			// 		return regex.test(callstack_html) && !excludeRegex.test(callstack_html)
			// 	else
			// 		return regex.test(callstack_html)
			// })

			this.currentFilteredFunctionState = { regexPattern: regexPattern, excludeRegexPattern: excludeRegexPattern, cntRegexPattern: cntRegexPattern, filteredFunctionIds: functionIdObjs.map(f => { return f.id }), hideReviewedState: this.currentFilteredFunctionState.hideReviewedState }
			this._view.webview.postMessage({ command: "searchFunctions", functionIdObjs: functionIdObjs || [], callstacks: callstacks })
		}
	}

	public joinGraphByFunction(graph_nodes: graphNode[], graph_edges: graphEdge[], f_id: string, direction: "outgoing" | "incoming" | null): CallGraph {
		let graph: CallGraph = { nodes: graph_nodes, edges: graph_edges }
		let f = this.functionDefinitionsMap.get(f_id)

		if (f?.callstackCount === 0) {
			// check if node doesn't exist in graph, then add it if not
			let node = graph.nodes.find(n => { return n.data.id === f_id })
			if (!node) {
				let source_code = this.getFileSource(f.filepath.split("#")[0], f.startLine, f.endLine)
				graph.nodes.push({ classes: 'l1', data: { id: f.id, parent: f.scope_id, title: this.getFunctionDescriptiveStr(f, true, true, true), content: source_code, isCollapsed: true } }) 
			}
			return graph
		}

		let mergeCallstacksIntoGraphParams: mergeCallstacksIntoGraphParams = {
			graph: graph,
			seen_nodes: graph.nodes.map(n => { return n.data.id }),
			seen_edges: [], // graph.edges.map(e => { return e.data.source })
			callstacksGraphParams: {
				callstacks: [],
				directional_edges_only: {
					target_function_id: f_id,
					include_direction: direction
				}
			}
		}
			
		mergeCallstacksIntoGraphParams.callstacksGraphParams.callstacks = f?.entrypoint_callstacks || []
		this.mergeCallstacksIntoGraph(mergeCallstacksIntoGraphParams)

		mergeCallstacksIntoGraphParams.callstacksGraphParams.callstacks = f?.exit_callstacks || []
		this.mergeCallstacksIntoGraph(mergeCallstacksIntoGraphParams)
		
		mergeCallstacksIntoGraphParams.callstacksGraphParams.callstacks = f?.other_callstacks || []
		this.mergeCallstacksIntoGraph(mergeCallstacksIntoGraphParams)
		

		// resolve transitive relationships
		
		// reset titles?
		
		// append related functions links w/ strikethrough
		graph.nodes = this.updateGraphRelatedFunctionHTMLLinks(graph.nodes)

		for (let n of graph.nodes) {
			if ('title' in n.data && n.data.isCollapsed !== false) {
				n.data.isCollapsed = true;
			}
		}

		// update function dectorators
		if (graph && 'nodes' in graph) {
			let node = graph.nodes.find(n => { return n.data.id === f_id })
			let f = this.functionDefinitionsMap.get(f_id)
			if (node && 'title' in node.data && f) {
				node.data.title = this.getFunctionDescriptiveStr(f, true, true, true)
			}
			//  = this.getFunctionDescriptiveStr(this.functionDefinitions[f_id], true, true, true)
		}

		return graph
	}

	public removeManuallyMappedRelationship(caller_id: string, callee_id: string) {
		// show confirmation popup
		vscode.window.showInformationMessage(`Remove manually mapped relationship:\n\ncaller: ${caller_id}\n\ncallee: ${callee_id}\n\nAre you sure?`, { modal: true }, 'Confirm')
			.then(selection => {
				if (selection === 'Confirm') {
					this.functionManualRelationship = this.functionManualRelationship.filter(relationship => { return !(relationship.caller_id === caller_id && relationship.callee_id === callee_id) })
					fs.writeFileSync(this.settings.manualFunctionRelationshipPath, JSON.stringify(this.functionManualRelationship))

					vscode.window.showInformationMessage('Removed, please manually refresh the graph!');
				}
			});

	}

	public manuallyMapFunctionRelationship(f_id: string, ctrl_pressed: boolean | null = null) {
		if (!this.lastManuallyMappedFunction_caller && !this.lastManuallyMappedFunction_callee) {
			// set first, takes ctrl into account
			if (ctrl_pressed === true) {
				this.lastManuallyMappedFunction_callee = f_id
			} else if (ctrl_pressed === false) {
				this.lastManuallyMappedFunction_caller = f_id
			} else {
				// prompt for caller or callee
				vscode.window.showInformationMessage(`Set as caller or callee?`, { modal: true }, 'Caller', 'Callee')
					.then(selection => {
						if (selection === 'Caller') {
							this.lastManuallyMappedFunction_caller = f_id
						} else if (selection === 'Callee') {
							this.lastManuallyMappedFunction_callee = f_id
						} else {
							// cancel
							return
						}
					})
			}

			return
		}


		// set second
		if (this.lastManuallyMappedFunction_caller && !this.lastManuallyMappedFunction_callee) {
			this.lastManuallyMappedFunction_callee = f_id
		} else if (!this.lastManuallyMappedFunction_caller && this.lastManuallyMappedFunction_callee) {
			this.lastManuallyMappedFunction_caller = f_id
		}


		let caller_id = this.lastManuallyMappedFunction_caller
		let callee_id = this.lastManuallyMappedFunction_callee
		this.lastManuallyMappedFunction_caller = null
		this.lastManuallyMappedFunction_callee = null

		if (!caller_id || !callee_id) {
			vscode.window.showErrorMessage(`Error mapping functions, please try again`)
			return
		}

		let already_mapped = this.functionManualRelationship.filter(relationship => { return relationship.caller_id === caller_id && relationship.callee_id === callee_id })
		if (already_mapped.length > 0) {
			vscode.window.showInformationMessage(`These functions are already mapped`)
			return
		}

		vscode.commands.executeCommand('workbench.action.focusActiveEditorGroup');
		vscode.window.showInformationMessage(`Manually map functions:\n\ncaller: ${caller_id}\n\ncallee: ${callee_id}\n\nAre you sure?`, { modal: true }, 'Confirm')
			.then(selection => {
				if (selection === 'Confirm') {
					this.functionManualRelationship.push({ caller_id: caller_id, callee_id: callee_id })
					
					fs.writeFileSync(this.settings.manualFunctionRelationshipPath, JSON.stringify(this.functionManualRelationship))

					// clear callstacksGraph cache + rebuild callstacks
					this.scopeGraphs = {}
					this.callstacksGraphCache = {}
					this.buildCallstacks()
					vscode.window.showInformationMessage('Confirmed!');
				}
			});
	}
 
	public async reloadWebview() {
		if (this._view) {
			this._view.webview.html = await this._getHtmlForWebview(this._view.webview);
		}
	}

	public async setWebviewHtml(html: string) {
		if (this._view) {
			this._view.webview.html = html
		}
	}

	private parseDecoratorStrToSet(decorator: string): Set<string> {
		decorator = decorator.trim().replaceAll("[", "").replaceAll("]", "").replaceAll("|", "")
		let m_buffer = ""
		let decorators = new Set<string>()
		for (let c of decorator) {
			if (this.isIconChar(c)) {
				decorators.add(c)
				continue
			}
			if (c === ",") {
				if (m_buffer.trim().length > 0)
					decorators.add(m_buffer.trim())
				m_buffer = ""
				continue
			}
			// else
			m_buffer += c
		}
		if (m_buffer.trim().length > 0) {
			decorators.add(m_buffer.trim())
		}
		return decorators
	}

	public setFuncOverrideProp(func_id: string, key: "decorator" | keyof FunctionOverride, val: string | boolean) {

		let f = this.functionDefinitionsMap.get(func_id)
		if (!f) {
			return
		}
		let f_override = this.functionOverrides.get(func_id)
		if (!f_override) {
			f_override = { decorators_to_add: new Set<string>(), decorators_to_remove: new Set<string>() }
			this.functionOverrides.set(func_id, f_override)
		}
		switch (key) {
			case "decorator":
				let f_scanned_decorator_arr = this.parseDecoratorStrToSet(f.scanned_decorator)
				let new_decorator_arr = this.parseDecoratorStrToSet(val as string)

				f_override.decorators_to_add = new Set<string>()
				f_override.decorators_to_remove = new Set<string>()

				// add to decorator_to_add (decorators in val that are not in f.decorator)
				for (let decorator of new_decorator_arr) {
					if (!f_scanned_decorator_arr.has(decorator)) {
						f_override.decorators_to_add.add(decorator)
					}
				}

				// add to decorator_to_remove (decorators in f.decorator that are not in val)
				for (let decorator of f_scanned_decorator_arr) {
					if (!new_decorator_arr.has(decorator)) {
						f_override.decorators_to_remove.add(decorator)
					}
				}

				break
			default:
				(f_override as any)[key] = val
				
		}
		

	}

	public async resolveWebviewView(
		webviewView: vscode.WebviewView,
		resolveContext: vscode.WebviewViewResolveContext,
		_token: vscode.CancellationToken,
	) {
		this._view = webviewView;
		webviewView.webview.options = getWebviewOptions(this._extensionUri)
		
		this.setWebviewHtml("<br>Loading & processing functions/callstacks...")

		if (this.functionDefinitions.length === 0 || this.scopeSummaries.length === 0) {
			await this.loadFunctionsAndScopeInfo()

			this.registerCodeLensProvider()
		}
		
		
		webviewView.webview.html = await this._getHtmlForWebview(webviewView.webview);

		webviewView.webview.onDidReceiveMessage(async message => {
			if (message.command === "open") {
				// opens file
				// const uri = vscode.Uri.parse(message.link);
				// const line = (+uri.fragment.substring(1)) - 1;
				// const startLine = uri.fragment.split('-')[0] ? Number(uri.fragment.split('-')[0].split(':')[0]) : 0;
				// const startCol = uri.fragment.split('-')[0].split(':')[1] ? Number(uri.fragment.split('-')[0].split(':')[1]) - 1 : 0;
				// const endLine = uri.fragment.split('-')[1] ? Number(uri.fragment.split('-')[1].split(':')[0]) : startLine;
				// const endCol = uri.fragment.split('-')[0].split(':')[1] ? Number(uri.fragment.split('-')[0].split(':')[1]) - 1 : 0;

				let uri = message.link
				let fragment = uri.split("#")[1] || ""

				const startLine = fragment.split('-')[0] ? Number(fragment.split('-')[0].split(':')[0]) : 0;
				let startCol = fragment.split('-')[0].split(':')[1] ? Number(fragment.split('-')[0].split(':')[1]) - 1 : this.defaultFileLineColumnOffset[uri.replace("file://", "").split(":")[0]] || 0

				
				const startLine_w_offset = this.getAuditCommentsLineOffset(uri, startLine) + startLine
				
				let pos1 = new vscode.Position(0, 0);
				let pos2 = new vscode.Position(0, 0);
				let sel = new vscode.Selection(pos1, pos2);

				let currentWorkspaceFolderUri: string
				if (vscode.workspace.workspaceFolders) {
					currentWorkspaceFolderUri = vscode.workspace.workspaceFolders[0].uri.toString().replace("file://", "")
				}

				// const folder_uri = vscode.Uri.file(uri.toString().split("#")[0].replace("file://", ""));
				const folder_uri = vscode.Uri.file(decodeURIComponent(uri.split("#")[0].replace("file://", "")));
				// click = open in active editor | ctrl click = open in new column
				const open_in_column = message.is_ctrl_click ? vscode.window.visibleTextEditors.length + 1 : vscode.window.activeTextEditor

				await vscode.commands.executeCommand('vscode.open', folder_uri, open_in_column).then((e) => {

					let editor = vscode.window.activeTextEditor
					if (editor)
						editor.selection = sel;

					let move_to_line = startLine_w_offset - 1
					if (move_to_line > 0) {
						vscode.commands
							.executeCommand("cursorMove", {
								to: "down",
								by: "line",
								value: startLine_w_offset - 1,
							})
					}
					if (startCol > 0) {
						vscode.commands.executeCommand("cursorMove", {
							to: "right",
							by: "character",
							value: startCol,
						})
					}

					// center screen
					if (editor)
						editor.revealRange(new vscode.Range(startLine_w_offset, startCol, startLine_w_offset, startCol), vscode.TextEditorRevealType.InCenter);


					if (currentWorkspaceFolderUri)
						vscode.commands.executeCommand('vscode.openFolder', currentWorkspaceFolderUri);
				})

				/**** .showTextDocument() will break global search when used. Keeping note here to remember in event of refactor. ****/
				// await vscode.window.showTextDocument(uri)
			}

			if (message.command === "content_to_new_file") {
				let filename = message.filename
				let content = this.decodeBase64Unicode(message.content)

				// const filepath = await this.appendAndCreateFolder('.vscode/fuzztemplates')

				// vscode open content in a new unsaved file
				const uri = vscode.Uri.parse(`untitled:${filename}`);
				const document = await vscode.workspace.openTextDocument(uri);

				// set focus on the new file
				const editor = await vscode.window.showTextDocument(document);
				
				
				editor.edit(editBuilder => {
					let lastLine = editor.document.lineCount-1
					let lastChar = editor.document.lineAt(editor.document.lineCount-1).range.end.character

					// clear all content
					editBuilder.delete(new vscode.Range(new vscode.Position(0, 0), new vscode.Position(lastLine, lastChar)))
					editBuilder.insert(new vscode.Position(0, 0), content);
				});
			}

			if (message.command === 'show_inheritance_graph') {
				if (this._view)
					this._view.webview.postMessage({ command: "showInScopeGraph", graph: this.getInheritanceGraph(message.scope_id) });
			}

			if (message.command === 'show_scope_graph') {
				if (this._view)
					this._view.webview.postMessage({ command: "showInScopeGraph", graph: await this.getScopeGraph(message.scope_id, message.scope_only, message.include_inherited_funcs, message.include_related_callstacks) });
			}

			if (message.command === 'set_function_sort_option') {
				this.functionSortOption = message.sortOption
				await this.showFilteredFunctionsRegex(this.currentFilteredFunctionState.regexPattern, this.currentFilteredFunctionState.excludeRegexPattern)
			}


			if (message.command === 'toggle_hide_reviewed') {
				this.currentFilteredFunctionState.hideReviewedState = message.hideReviewedState
				await this.showFilteredFunctionsRegex(this.currentFilteredFunctionState.regexPattern, this.currentFilteredFunctionState.excludeRegexPattern)
			}

			if (message.command === "show_function") {
				this.showFunction(message.function_id, message.navigated_from_history, message.mode, message.include_related_callstacks)
			}

			if (message.command === "show_scope") {
				this.showScope(message.scope_id, message.checkbox_ids_to_check)
			}

			if (message.command === "search_functions") {
				await this.showFilteredFunctionsRegex(message.regex, message.exclude_regex, message.cnt_regex, message.mode)
			}

			if (message.command === "search_scopes") {
				this.showFilteredScopesRegex(message.regex, message.exclude_regex)
			}

			if (message.command === "mark_function_reviewed") {
				let func = this.functionDefinitionsMap.get(message.funcId)
				if (func) {
					func.reviewed = message.value;
					let f_overrides = this.functionOverrides.get(func.id)
					if (f_overrides) { f_overrides.reviewed = func.reviewed }

					// TODO: move to updateCache function
					// update graph cache
					Object.keys(this.callstacksGraphCache).forEach((key: string) => {
						const graph: CallGraph = this.callstacksGraphCache[key];

						for (let node of graph.nodes) {
							if (func && 'title' in node.data && node.data.id === func.id) {
								node.data.title = this.getFunctionDescriptiveStr(func, true, true, true)
							}
						}
					});

					this.buildCallstacks()
				}
			}

			if (message.command === "set_hide_callstacks_from_function") {
				let func = this.functionDefinitionsMap.get(message.f_id)


				if (func) {
					let append_to_graph = false
					if (message.direction === "incoming") {
						func.hide_incoming_callstacks = message.value ? message.value : !func.hide_incoming_callstacks
						func.decorator = func.hide_incoming_callstacks ? func.decorator + "🔼" : func.decorator.replaceAll("🔼", "")
						append_to_graph = !func.hide_incoming_callstacks
					}
					if (message.direction === "outgoing") {
						func.hide_outgoing_callstacks = message.value ? message.value : !func.hide_outgoing_callstacks
						func.decorator = func.hide_outgoing_callstacks ? func.decorator + "🔽" : func.decorator.replaceAll("🔽", "")
						append_to_graph = !func.hide_outgoing_callstacks
					}
					
					// set overrides
					this.setFuncOverrideProp(func.id, "hide_incoming_callstacks", func.hide_incoming_callstacks || false)
					this.setFuncOverrideProp(func.id, "hide_outgoing_callstacks", func.hide_outgoing_callstacks || false)
					this.setFuncOverrideProp(func.id, "decorator", func.decorator)
					


					this.scopeGraphs = {}
					this.callstacksGraphCache = {}
					this.buildCallstacks()

					// extend graph by function (if adding back, either incoming/outgoing)
					// will reshow graph to update decorator of current function and append callstacks (if needed)
					if (message.graph_id) {
						const graph = this.joinGraphByFunction(message.graph_nodes, message.graph_edges, message.f_id, message.direction)
						
						// send message back to client to update
						if (this._view)
							this._view.webview.postMessage({ command: "setGraph", graph_id: message.graph_id, graph: graph, f_id: message.f_id });
					}
				}
			}

			if (message.command === "mark_all_reviewed") {
				vscode.window.showInformationMessage(`Mark all functions as reviewed?`, { modal: true }, 'Reviewed', "Unreviewed")
					.then(async selection => {
						if (!selection) {
							return
						}

						this.functionDefinitions
							.filter(f => { return this.currentFilteredFunctionState.filteredFunctionIds.includes(f.id) })
							.forEach(f => {
								// f.reviewed = message.reviewed
								f.reviewed = selection === 'Reviewed'
								this.setFuncOverrideProp(f.id, "reviewed", f.reviewed || false)
		
								// TODO: move to updateCache function
								// update graph cache
								Object.keys(this.callstacksGraphCache).forEach((key: string) => {
									const graph: CallGraph = this.callstacksGraphCache[key];
		
									for (let node of graph.nodes) {
										if ('title' in node.data && node.data.id === f.id) {
											node.data.title = this.getFunctionDescriptiveStr(f, true, true, true)
										}
									}
								});
							})
		
		
						await this.showFilteredFunctionsRegex(this.currentFilteredFunctionState.regexPattern, this.currentFilteredFunctionState.excludeRegexPattern)
						this.buildCallstacks()
					})
			}

			if (message.command === "bulk_update_decorator") {
				vscode.window.showInformationMessage(`Bulk update decorator:`, { modal: true}, 'Add', 'Remove' )
					.then(selection => {

						if (!selection) {
							return
						}

						vscode.window.showInputBox({ prompt: `Enter decorator to ${selection.toLowerCase()}:`}).then(async val => {
							if (!val) {
								return
							}

							this.functionDefinitions
								.filter(f => { return this.currentFilteredFunctionState.filteredFunctionIds.includes(f.id) })
								.forEach(f => {
										let did_update = false
										if (selection === 'Add' && !f.decorator.includes(val)) {
											f.decorator = f.decorator + val
											did_update = true
										} else if (selection === 'Remove' && f.decorator.includes(val)) {
											f.decorator = f.decorator.replaceAll(val, "")
											did_update = true
										}
										this.setFuncOverrideProp(f.id, "decorator", f.decorator)

										if (!did_update) {
											return
										}
								
										// TODO: move to updateCache function
										// update graph cache
										Object.keys(this.callstacksGraphCache).forEach((key: string) => {
												const graph: CallGraph = this.callstacksGraphCache[key];
									
										for (let node of graph.nodes) {
											if ('title' in node.data && node.data.id === f.id) {
												node.data.title = this.getFunctionDescriptiveStr(f, true, true, true)
											}
										}
									});
								})
							
							await this.showFilteredFunctionsRegex(this.currentFilteredFunctionState.regexPattern, this.currentFilteredFunctionState.excludeRegexPattern)
							this.buildCallstacks()
							
							vscode.window.showInformationMessage(`Confirmed! ${selection} - ${val}`);
							
						})
					});						
			}

			
			if (message.command === "add_detectors") {
				// prompt for impact
				let impact = await vscode.window.showQuickPick(
					['Informational', 'Low', 'Medium', 'High', 'Critical'],
					{ placeHolder: 'Select impact for detectors to add' }
				);
				if (!impact) {
					return
				}
				// prompt for confidence
				let confidence = await vscode.window.showQuickPick(
					['Low', 'Medium', 'High'],
					{ placeHolder: 'Select confidence for detectors to add' }
				);
				if (!confidence) {
					return
				}
				// prompt for check name
				let check = await vscode.window.showInputBox({ prompt: 'Enter check name for detectors to add (e.g. my_custom_check)' });
				let description_postfix = await vscode.window.showInputBox({ prompt: 'Enter description for detectors to add (e.g. My custom check description)' });


				
				type Detection = {
					id: string
					impact: string
					confidence: string
					check: string  // grouping
					description: string
					first_markdown_element: string
					elements: DetectionNode[]
				}

				type DetectionNode = {
					type: "function"
					name: string
					source_mapping: {
						filename_relative: string
						filename_absolute: string
						filename_short: string
						lines: number[]
						starting_column: number
						ending_column: number
					}
				}

				let detections: Detection[] = []

				let workspacePath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || ""
				for (let f of message.functions) {
					let f_lookup = this.functionDefinitionsMap.get(f.id)
					let description_prefix = ""
					if (f_lookup) {
						description_prefix = `${f_lookup.filename}.${f_lookup.functionName} | `
					}

					for (let loc of f.locs) {
						// id is hash of filepath + startline + check
						let id = createHash("md5").update(`${loc.filepath}:${loc.lineNum}:${check}`).digest("hex");

						let description = description_prefix + loc.content + "\n" + description_postfix

						let detection: Detection = {
							id: id,
							impact: impact,
							confidence: confidence,
							check: check || "custom_check",
							description: description,  // shown on each ele
							first_markdown_element: `${loc.filepath.split("#")[0].split("/").slice(-1)[0]}#L${loc.lineNum}`,
							elements: [
								{
									type: "function",
									name: "<blank>",
									source_mapping: {
										filename_relative: loc.filepath.split("#")[0].replace(workspacePath + "/", ""),
										filename_absolute: loc.filepath.split("#")[0],
										filename_short: loc.filepath.split("#")[0].split("/").slice(-1)[0],
										lines: Array.from({ length: (loc.lineNum - loc.lineNum + 1) }, (_, i) => i + loc.lineNum),
										starting_column: loc.colNum,
										ending_column: loc.colNum
									}
								}
							]
						}
	
						detections.push(detection)
					}
				}

				// add detectors to slither detectors file
				let existing_detections: Detection[] = []
				let detectorsPath = path.join(workspacePath, this.DETECTORS_PATH);

				if (!fs.existsSync(detectorsPath)) {
					// create directory and file
					fs.mkdirSync(path.dirname(detectorsPath), { recursive: true });
					fs.writeFileSync(detectorsPath, JSON.stringify([], null, 4));
				}
				
				let existing_detections_content = fs.readFileSync(detectorsPath, 'utf8')
				try {
					existing_detections = JSON.parse(existing_detections_content)

					// add detections with new id
					let added = 0
					let updated = 0
					for (let detection of detections) {
						let existing = existing_detections.find(d => { return d.id === detection.id })
						if (!existing) {
							existing_detections.push(detection)
							added++
						} else {
							// update description
							existing.description = detection.description
							existing.impact = detection.impact
							existing.confidence = detection.confidence
							updated++
						}
					}
					fs.writeFileSync(detectorsPath, JSON.stringify(existing_detections, null, 4))
					vscode.window.showInformationMessage(`Added ${added} | updated ${updated} detectors to ${detectorsPath}`);
				} catch (e) {
					vscode.window.showErrorMessage(`Failed to parse existing detectors file: ${detectorsPath}. Please fix the file and try again.`)
					return
				}
			

				vscode.window.showInformationMessage(`Bulk add detectors to functions`)
			}

			if (message.command === "load") {
				this.scopeGraphs = {}
				this.callstacksGraphCache = {}
				await this.loadFunctionsAndScopeInfo()
				webviewView.webview.html = await this._getHtmlForWebview(webviewView.webview);
				if (this._view) {
					this._view.webview.postMessage({ command: "setElesDisabled", selector: "#btn-load", is_disabled: false });
					
					if (message.lastFunction) {
						this.showFunction(message.lastFunction.id)
						if (message.lastScope) {
							let scope = this.scopeSummaries.find(scope => { return scope.id == message.lastScope.scope.id })
							this._view.webview.postMessage({ command: "displayScope", scope: scope, checkbox_ids_to_check: message.lastScope.checkbox_ids_to_check });
						}
					}
					// this._view.webview.postMessage({ command: "displayFunction", function: message.lastFunction, navigated_from_history: false });
				}
			}

			if (message.command === "send_to_copilot_chat") {
				if (message.message) {
					sendToCopilotChat(message.message)
				}
			}
			
			if (message.command === "save") {
				await this.saveFunctionInfo()
				await this.saveSettings()
				if (this._view)
					this._view.webview.postMessage({ command: "setElesDisabled", selector: "#btn-save", is_disabled: false });
			}

			if (message.command === "update_decorator") {
				let func = this.functionDefinitionsMap.get(message.funcId)
				
				if (func) {
					func.decorator = message.value
					this.setFuncOverrideProp(func.id, "decorator", func.decorator)
				}
				this.buildCallstacks()
			}

			if (message.command === "update_function_notes") {
				let func = this.functionDefinitionsMap.get(message.funcId)
				
				if (func) {
					func.function_notes = message.value
					this.setFuncOverrideProp(func.id, "function_notes", func.function_notes || "")
				}
				
			}

			if (message.command === "toggleHelpHTML") {
				if (this._view)
					this._view.webview.postMessage({ command: "toggleHelpHTML", helpHTML: this.helpHTML });
			}

			if (message.command === "togogle_interesting_functions_mode") {
				this.settings.showAllFunctions = message.value === "true" ? true : false
			}

			if (message.command === "requestFuncStateVarReadWriteMapping") {
				if (this._view)
					this._view.webview.postMessage({ command: "receiveFuncStateVarReadWriteMapping", mapping: this.funcStateVarReadWrittenMapping });
			}

			// graph commands
			if (message.command === "save_graph") {
				this.saveFile(message.content)
			}

			if (message.command === "load_graph") {
				let file_obj = await this.loadFile()
				
				// load graph @ message.graph_id
				if (this._view)
					this._view.webview.postMessage({ command: "setGraph", graph_id: message.graph_id, filename: file_obj.filename, graph: JSON.parse(file_obj.content) });
			}			
			
			if (message.command === 'manually_map_function_relationship') {

				this.manuallyMapFunctionRelationship(message.f_id, message.ctrl_pressed)
			}
			
			if (message.command === 'remove_manually_mapped_relationship') {
				this.removeManuallyMappedRelationship(message.caller_id, message.callee_id)
			}
			
			
			if (message.command === "expand_graph_by_function") {
				const graph = this.joinGraphByFunction(message.graph_nodes, message.graph_edges, message.f_id, message.direction)

				// load graph @ message.graph_id
				if (this._view)
					this._view.webview.postMessage({ command: "setGraph", graph_id: message.graph_id, graph: graph, f_id: message.f_id });
			}

			
			if (message.command === "expand_graph_by_scope") {
				let functions = this.functionDefinitions.filter(f => { return f.scope_id === message.scope_id && f.is_inherited === false })
				let graph: CallGraph = { nodes: [], edges: [] }
				for (let f of functions) {
					graph = this.joinGraphByFunction(message.graph_nodes, message.graph_edges, f.id, null)
				}
				// const graph = this.joinGraphByFunction(message.graph_nodes, message.graph_edges, message.f_id, message.direction)

				// load graph @ message.graph_id
				if (this._view)
					this._view.webview.postMessage({ command: "setGraph", graph_id: message.graph_id, graph: graph, f_id: message.f_id });
			}

			if (message.command === "eval_failure") {
				vscode.window.showErrorMessage(`If unsafe eval is not enabled, please enable in extension settings.\n${message.error}`)
			}

			if (message.command === "show_content_in_browser") {
				showContentInBrowser(message.content)
			}

			if (message.command === "toggle_ctnt_uses_gitignore") {
				this.settings.ctnt_uses_gitignore = message.value === "true" ? true : false
			}

			if (message.command === "force_data_update") {
				vscode.window.showInformationMessage(`Data update has been queued.`);
				// create file .vscode/ext-static-analysis/cache/force_update
				let force_update_path = path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || "", ".vscode", "ext-static-analysis", "cache", "force_update")
				fs.mkdirSync(path.dirname(force_update_path), { recursive: true });
				fs.writeFileSync(force_update_path, "")
			}
		});
	}



	private async _getHtmlForWebview(webview: vscode.Webview) {
		// Get the local path to main script run in the webview, then convert it to a uri we can use in the webview.
		const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'main.js'));

		const scriptMarkUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'mark.min.js'));
		const scriptPakoUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'pako.min.js'));

		const scriptCytoscapeUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'cytoscapes', 'cytoscape.min.js'));
		const scriptElkUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'cytoscapes', 'elk.bundled.js'));
		

		const scriptElkAdaptorUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'cytoscapes', 'cytoscape-elk.js'));
		const scriptDagreUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'cytoscapes', 'dagre.min.js'));
		const scriptCytoscapeDagreUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'cytoscapes', 'cytoscape-dagre.js'));
		const scriptCytoscapeMainUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'cytoscapes', 'main.js'));
		const scriptCytoscapeNodeLabelUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'cytoscapes', 'cytoscape-html-node-label.js'));

		const HighlightUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'highlight', 'highlight.min.js'));
		const HighlightSolidityUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'highlight', 'solidity.min.js'));
		const styleHighlightUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'highlight', 'highlight.min.css'));

		const scriptPrismUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'prism', 'prism-core.min.js'));
		const stylePrismUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'prism', 'prism.min.css'));
		const stylePrismTomorrowNightThemeUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'prism', 'prism-tomorrow.min.css'));
		const scriptPrismSolidityUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'prism', 'prism-solidity.min.js'));
		// const scriptPrismAutoloaderUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'prism', 'prism-autoloader.min.js'));

		const nonce = getNonce();

		// Local path to css styles
		const styleMainPath = vscode.Uri.joinPath(this._extensionUri, 'media', 'main.css');

		// Uri to load styles into webview
		const stylesMainUri = webview.asWebviewUri(styleMainPath);

		const enableUnsafeEval = vscode.workspace.getConfiguration('static-analysis').get<boolean>('enableUnsafeEval');

		return `<!DOCTYPE html>
			<html lang="en">
				
				<head>
					<meta charset="UTF-8">

					<!--
						Use a content security policy to only allow loading styles from our extension directory,
						and only allow scripts that have a specific nonce.
						(See the 'webview-sample' extension sample for img-src content security policy examples)
					-->
					<!-- 
						<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource}; script-src 'nonce-${nonce}';">
					-->
					<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}' ${enableUnsafeEval ? "'unsafe-eval'" : ""};">

					<meta name="viewport" content="width=device-width, initial-scale=1.0">
			
					<link href="${stylesMainUri}" rel="stylesheet">
					<link href="${styleHighlightUri}" rel="stylesheet">
					<link href="${stylePrismUri}" rel="stylesheet">

					<title>Static Analysis: Functions View</title>
				</head>
				<body>

					<header class='sticky-header'>
						<span id='new-data-state'></span>
						<span class='icon' id='settings-btn'>⚙️</span>
						<span class='icon' id='send-to-copilot-chat-btn'>💬</span>
						<button id='btn-save'>save</button>
						<button id='btn-load'>load</button>
						${this.helpHTML ? "<button id='toggle-help'>Help</button>" : ''}
						<button id='show-all-inheritance-graph-btn'>Show Inheritance Graph</button>
						<button id='show-all-scope-graph-btn'>Show In Scope Graph</button>
						<button id='show-callstacks-graph-with-search-term-btn'>Show Callstacks Graph w/ Search Term</button>
						${ this.searchTemplates.length > 0 ? "<select id='select-search-template'><option></option>" : '' }
							${this.searchTemplates.map((t, i) => { 
								let include = !t.include ? '' : t.include.replace(/"/g, '&quot;')
								let exclude = !t.exclude ? '' : t.exclude.replace(/"/g, '&quot;')
								let highlight = !t.highlight ? '' : t.highlight.replace(/"/g, '&quot;')
								
								return `<option data-include="${include}" data-exclude="${exclude}" data-highlight="${highlight}">${t.name || ""}: ${t.include} | ${t.exclude}</option>` }).join("")
							}
						${ this.searchTemplates.length > 0 ? "</select>" : '' }
						<button id='search-functions'>s: Fn</button>
						<button id='search-scopes'>s: Scps</button>
						<input id='function-selector-textbox' class='input-textbox' placeholder='filter functions' type='text' />
						<input id='function-selector-exclude-textbox' class='input-textbox' placeholder='exclude functions regex' type='text' />
						<button id='search-functions-content'>s: Ctnt</button>
						<input id='search-textbox' class='input-textbox' placeholder='search/highlight regex' type='text' />
						<button id='function-back'>back</button>
						<button id='function-forward'>forward</button>
						<button id='btn-mark-all-reviewed' disabled>Mak All (Un)Reviewed</button>
						<button id='btn-bulk-update-decorator' disabled>+/- decorator</button>
						<span id='selectedStateVar' style='float: right'></span>
						<br>
						<span id='decorator-description'>Unique decorator unicode (save/load to refresh): 
							<span id='decorator-description-value'>${Array.from(this.decoratorUnicode).map(c => { return `<a style='cursor:pointer' search_regex="${c}">${c}</a>` }).join('')}</span>
							<span style='float: right; margin-right: 5px'>Created by: <a href='https://alecmaly.com' target='_blank'>alecmaly.com</a></span>
						</span>   
						<div id='settings' style='display: none'>
							<button id='force-data-update-btn' style='background-color: darkturquoise'>Force LSP Update</button>
							<span class='spacer'></span>
							<select id='select-cytoscapes-layout'>
								<option>dagre</option>
								<option>elk</option>
							</select>
							<select id='select-syntax-highlighter'>
								<option>Prism</option>
								<option>HighlightJS</option>
								<option>Disabled</option>
							</select>
							<select id='select-function-sort'>
								<option>Alpha. + Line #</option>
								<option>Alpha. + SLOC</option>
								<option>SLOC</option>
								<option>Alpha. + # Callstacks</option>
								<option># Callstacks</option>
							</select>
							<select id='toggle-reviewed'>
								<option>Hide Reviewed Except In Scope</option>
								<option>In Scope Only</option>
								<option>Hide Reviewed</option>
								<option>Show Reviewed</option>
							</select>
							<button id='callstacks-graph-mode-btn' value="Combined">Fn Graph Mode: Combined</button>
							<button id='show-all-functions-btn' value="${this.settings?.showAllFunctions === true ? 'true' : 'false'}">${this.settings.showAllFunctions ? 'Showing All Functions' : 'Showing Interesting Functions'}</button>
							<button id='include-related-callstacks-btn' value="false">Excluding Related Callstacks</button>
							<button id='ctnt-uses-gitignore-btn' value="${this.settings?.ctnt_uses_gitignore === true ? 'true' : 'false'}">${this.settings.ctnt_uses_gitignore ? 'Ctnt uses .gitignore' : 'Ctnt doesn\'t use .gitignore'}</button>
						</div>
						<div id='help'></div>
					</header>


					<div id='content'>
						<ul id='functions-list'></ul>
						
						<div id='scope-graph-container' style='display: none'></div>

						<div class='container'>
							<div id='function-summary'></div>
							<div id='resizable-handle'></div>
							<div id='scope-detail'></div>
						</div>
					</div>
				
					
					<span style="display: none" id='copilot-ctx'>${await getCopilotContext()}</span>
					<script nonce="${nonce}" src="${scriptUri}"></script>
					<script nonce="${nonce}" src="${scriptMarkUri}"></script>
					<script nonce="${nonce}" src="${scriptPakoUri}"></script>

					<!-- Cytoscape imports -->
					<script nonce="${nonce}" src="${scriptCytoscapeUri}"></script>
					<script nonce="${nonce}" src="${scriptElkUri}"></script>
					<script nonce="${nonce}" src="${scriptElkAdaptorUri}"></script>
					<script nonce="${nonce}" src="${scriptDagreUri}"></script>
					<script nonce="${nonce}" src="${scriptCytoscapeDagreUri}"></script>
					<script nonce="${nonce}" src="${scriptCytoscapeMainUri}"></script>
					<script nonce="${nonce}" src="${scriptCytoscapeNodeLabelUri}"></script>
					
					<script nonce="${nonce}" src="${HighlightUri}"></script>
					<script nonce="${nonce}" src="${HighlightSolidityUri}"></script>

					<script nonce="${nonce}" src="${scriptPrismUri}"></script>
					<script nonce="${nonce}" src="${scriptPrismSolidityUri}"></script>

				</body>
			</html>`;
	}
}


function getNonce() {
	let text = '';
	const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	for (let i = 0; i < 32; i++) {
		text += possible.charAt(Math.floor(Math.random() * possible.length));
	}
	return text;
}


function escapeRegExp(text: string) {
    try {
        new RegExp(text)
        return text
    } catch (e) {
        return text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
    }
}
