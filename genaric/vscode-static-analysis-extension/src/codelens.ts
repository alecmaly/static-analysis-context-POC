'use strict';
/** 
 * @author github.com/tintinweb
 * @license GPLv3
 * 
 * 
 * */

import * as vscode from 'vscode';
import { FunctionResult, SourceFilesHashmap } from './types';



export class StaticAnalysisCodeLensProvider implements vscode.CodeLensProvider {
    functions: FunctionResult[]; 
    getAuditCommentsLineOffset: Function;
    getFileLines: Function;
    sourceFilesCache: any;

    constructor(g_workspace: any, functions: FunctionResult[], getAuditCommentsLineOffset: Function, getFileLines: Function, sourceFilesCache: SourceFilesHashmap) {
        this.functions = functions
        this.getAuditCommentsLineOffset = getAuditCommentsLineOffset

        this.getFileLines = getFileLines
        this.sourceFilesCache = sourceFilesCache

    }

    provideCodeLenses(document: vscode.TextDocument, token: vscode.CancellationToken) : vscode.CodeLens[] | Thenable<vscode.CodeLens[]> {
        let lenses: vscode.CodeLens[] = [];

        let functionsToMap = this.functions.filter(f => { return f.filepath.toLowerCase().split("#")[0] === document.fileName.toLowerCase() })

        for (let f of functionsToMap) {
            let offset = this.getAuditCommentsLineOffset(f.filepath, f.startLine)
            let range = new vscode.Range(f.startLine - 1 + offset, 0, f.startLine - 1 + offset, 0);

            lenses.push(new vscode.CodeLens(range, {
                command: 'static-analysis.navigateToFunction',
                title: `funcSummary${f.decorator ? " " + f.decorator : ""}`,
                arguments: [f]
            }))

            lenses.push(new vscode.CodeLens(range, {
                command: 'static-analysis.references',
                title: `referencesX (${f.called_at?.length || 0})`,
                arguments: [f]
            }))

            lenses.push(new vscode.CodeLens(range, {
                command: 'static-analysis.manuallyMapFunctionRelationship',
                title: '🪢',
                arguments: [f]
            }))
        }

        return lenses;
    }
}
