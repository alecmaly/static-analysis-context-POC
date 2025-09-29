// @ts-nocheck

import * as vscode from 'vscode';
import * as config from "./config";
import * as slither from "./slither";
import * as slitherResults from "./slitherResults";
import { ExplorerNode } from "./explorerTree";
import { Logger } from "./logger";

// Generic tree node implementation.
export class DetectorFilterNode extends vscode.TreeItem {
    public readonly detector : slitherResults.SlitherDetector;
    public checked : boolean = true;
    constructor(detector : slitherResults.SlitherDetector, checked : boolean, detail: string) {
        // let detail = "this is a test (23-High,Low) more High stuff"
        
        let label_str = `${detector.check}: (${detail}) ${detector.title}\n${detector.description}\n\nImpact: ${detector.impact}\nConfidence: ${detector.confidence}`
        let search_strings = ['High,', 'Medium,']

        function getIndicesOf(searchStr, str, caseSensitive) {
            var searchStrLen = searchStr.length;
            if (searchStrLen == 0) {
                return [];
            }
            var startIndex = 0, index, indices = [];
            if (!caseSensitive) {
                str = str.toLowerCase();
                searchStr = searchStr.toLowerCase();
            }
            while ((index = str.indexOf(searchStr, startIndex)) > -1) {
                indices.push([index, index + searchStr.length]);
                startIndex = index + searchStrLen;
            }
            return indices;
        }

        var indices = []
        for (let str of search_strings) {
            indices.push(getIndicesOf(str, label_str))  // Highlight High / Medium severity issues
        }


        let label_obj = {label: label_str, highlights: indices.flat()}
        super(label_obj, vscode.TreeItemCollapsibleState.None);

        // super(`${detector.check}: (${count}) ${detector.title}\n${detector.description}\n\nImpact: ${detector.impact}\nConfidence: ${detector.confidence}`, vscode.TreeItemCollapsibleState.None);
        this.detector = detector;
        this.checked = checked;
        this.command = {
            title: "",
            command: "slither.clickedDetectorFilterNode",
            arguments: [this],
        };
    }
}

// The explorer/treeview for slither analysis results.
export class DetectorFilterTreeProvider implements vscode.TreeDataProvider<DetectorFilterNode> {

    // Create our event emitters for the changed tree event.
    public changeTreeEmitter: vscode.EventEmitter<any> = new vscode.EventEmitter<any>();
    public readonly onDidChangeTreeData: vscode.Event<any> = this.changeTreeEmitter.event;

    // Create a callback function for signaling 
    public changedEnabledFilters : (() => void)[] = [];

    // A node which is not rendered itself, but contains all nodes which will be shown.
    private detectorFilterNodes : DetectorFilterNode[] = [];

    private tree_detected: ExplorerNode;

    constructor(private context: vscode.ExtensionContext) {
    }

    public setDetectorFilterCounts(tree_detected_: ExplorerNode) {
        this.tree_detected = tree_detected_;

        this.populateTree()
    }

    public async populateTree() {
        function getCircularReplacer() {
            const seen = new WeakSet();
            return function(key: any, value: any) {
                if (typeof value === "object" && value !== null) {
                    if (seen.has(value)) {
                        return;
                    }
                    seen.add(value);
                    }
                return value;
            };
        }
        
        const obj: ExplorerNode = this.tree_detected;
        obj.self = obj;
        const json = JSON.stringify(obj, getCircularReplacer());

        function groupByCount(arr) {
            const count = {};
            for (const item of arr) {
              count[item] = (count[item] || 0) + 1;
            }
            return count;
        }

        // let analysis_results_detectors = obj.nodes.map(severity => { return severity.nodes.filter(ele=>{return ele != null}).map(ele=>{ return ele ? { name: ele.typeNodeParent.originalLabel.split("\n")[0], count: ele.result.elements.length }: '' }) })
        let analysis_results_detectors = obj.nodes.map(severity => { return severity.nodes.filter(ele=>{return ele != null}).map(ele=>{ return ele ? ele.typeNodeParent.originalLabel.split("\n")[0].split(":")[0] : '' }) })
        let detector_hit_counts = groupByCount(analysis_results_detectors.flat())
        
        // Logger.log(JSON.stringify(detector_counts, getCircularReplacer()))
        
        // Logger.log(analysis_results_detectors.flat().length)
        // Logger.log(json)


        // Add a node for each detector to the tree.
        this.detectorFilterNodes = [];
        let detectors = slither.detectors
        let output = []
        for (let detector of detectors) {
            // Determine if this detector is visible or not
            let checked : boolean = true;
            if (config.userConfiguration.hiddenDetectors) {
                checked = config.userConfiguration.hiddenDetectors.indexOf(detector.check) < 0;
            }
            
            // Logger.log(`${detector.check} : ${detector.title}`)
            // Logger.log(`${JSON.stringify(detector)}`)
            
            // Create the node for this detector and add it to the list.
            let count = detector_hit_counts[`${detector.check}`] || 0

            if (count > 0) {
                let detectorFilterNode : DetectorFilterNode = new DetectorFilterNode(detector, checked, `${count} - ${detector.impact},${detector.confidence}`);
                this.refreshNodeIcon(detectorFilterNode);
                output.push({ check: detector.check, count: count, impact: detector.impact, detectorFilterNode: detectorFilterNode})
                // this.detectorFilterNodes.push(detectorFilterNode);
            }
        }



        let sortedArray = output.sort((a, b) => {
            const impactOrder = { "Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Informational": 5 };
            if (impactOrder[a.impact] !== impactOrder[b.impact]) {
                return impactOrder[a.impact] - impactOrder[b.impact];
            } else {
                // return a.count - b.count;
                return a.check - b.check;
            }
        });
        
        for (let row of sortedArray) {
            // let detectorFilterNode : DetectorFilterNode = new DetectorFilterNode(detector, checked, `${count} - ${detector.impact},${detector.confidence}`);
            // this.refreshNodeIcon(detectorFilterNode);
            this.detectorFilterNodes.push(row.detectorFilterNode);
        }


        // Fire the event to refresh our tree and invoke any callback.
        await this.fireChangedEnabledFilters();
    }

    private async fireChangedEnabledFilters() {
        // Fire an event to change our detector filter tree
        this.changeTreeEmitter.fire();

        // If we have callback handlers, fire them all.
        if (this.changedEnabledFilters != null) {
            for(let callback of this.changedEnabledFilters) {
                await callback();
            }
        }
    }

    private refreshNodeIcon (node :DetectorFilterNode) {
        if (node.checked) {
            node.iconPath = { 
                light: this.context.asAbsolutePath("resources/check-light.svg"),
                dark: this.context.asAbsolutePath("resources/check-dark.svg"),
            };
        }
        else {
            node.iconPath = undefined;
        }
    }

    public async toggleAll() {
        // If we have any items unchecked, we'll check all items. Otherwise we uncheck them all.
        let newCheckedState : boolean = false;
        for(let node of this.detectorFilterNodes) {
            if(!node.checked) {
                newCheckedState = true;
            }
        }

        // Set the checked state of all items.
        for(let node of this.detectorFilterNodes) {
            node.checked = newCheckedState;
            this.refreshNodeIcon(node);
        }

        // Fire the event to refresh our tree and invoke any callback.
        await this.fireChangedEnabledFilters();
    }

    public async getHiddenDetectors() : Promise<Set<string>> {
        // Create a new set
        let hiddenDetectors : Set<string> = new Set<string>();

        // For each hidden detector, add it to the set
        for(let node of this.detectorFilterNodes) {
            if (!node.checked) {
                hiddenDetectors.add(node.detector.check);
            }
        }

        // Return the resulting set.
        return hiddenDetectors;
    }

    public async clickedNode(node : DetectorFilterNode) {
        // Toggle the checked state
        node.checked = !node.checked;
        this.refreshNodeIcon(node);

        // Fire the event to refresh our tree and invoke any callback.
        await this.fireChangedEnabledFilters();
    }

    public getTreeItem(element: DetectorFilterNode): vscode.TreeItem {
        return element;
    }

    public getChildren(element?: DetectorFilterNode): DetectorFilterNode[] | Thenable<DetectorFilterNode[]> {
        // Obtain our list of detectors
        return this.detectorFilterNodes;
    }
}
