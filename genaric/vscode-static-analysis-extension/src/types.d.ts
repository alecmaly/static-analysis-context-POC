// imported from file
export interface ScopeSummary {
	id: string
	name: string
	type: string // "class" | "library" | "module" | "file" | "contract" | ... etc.
	scope_summary_html: string
	inherits?: string[]
	inherits_recursive?: string[]
	inherits_from?: string[]
	inherits_from_recursive?: string[]
	backgroundColor?: string
}

// built from functionResults & lookup to scopeSummary
interface ScopeDefinition {
	id: string,
	name: string,
	type: string // "class" | "library" | "module" | "file" | "contract" | ... etc.
	decorator: string,
	filepath: string,
	numFunctions_inherited: number
	numFunctions: number
	scope_summary?: ScopeSummary
}

export interface SearchTemplate {
	name: string
	include: string
	exclude: string
	highlight: string
}

export interface FunctionOverride {
	decorators_to_add: Set<string>, // decorators to add to the function
	decorators_to_remove: Set<string>, // decorators to remove from the function
	reviewed?: boolean, // whether the function has been reviewed
	hide_incoming_callstacks?: boolean, // hide incoming callstacks for this function
	hide_outgoing_callstacks?: boolean, // hide outgoing callstacks for this function
	function_notes?: string, // notes for the function
}


export interface Loc {
	filepath: string,
	lineNum: number,
	colNum: number,
	content: string
}

export interface FunctionResult {
	id: string,							//	<functionName>,<filepath>#<startLine>:<startCol>
	scope_id: string,
	functionName: string,
	functionParameters: string,
	functionReturns: string,
	startLine: number,
	endLine: number,
	startCol: number,
	filepath: string,
	filepath_body: string,
	qualifiedName_full: string,
	qualifiedName: string,
	filename: string,
	scanned_decorator: string,
	decorator: string,
	state_var_summary: string,
	entrypoint_callstacks: number[],
	exit_callstacks: number[],
	other_callstacks: number[],
	entrypoint_callstacks_html: string,
	exit_callstacks_html: string,
	other_callstacks_html: string,
	related_callstacks_html: string,
	entrypoint_callstacks_graph: CallGraph,
	exit_callstacks_graph: CallGraph,
	other_callstacks_graph: CallGraph,
	callstacks_graph: CallGraph,
	related_callstacks_graph: CallGraph,
	function_summary_html: string,
	tainted_locations_count: number,
	tainted_locations_html: string,
	reviewed: boolean | undefined,
	hide_incoming_callstacks: boolean | undefined,
	hide_outgoing_callstacks: boolean | undefined,
	function_notes?: string,
	checkbox_ids_to_check: string[],
	checkbox_ids_to_color: string[],
	related_functions_html: string,
	callstackCount: number,
	is_inherited?: boolean,
	is_shadowed?: boolean,
	relatedFunctions: string[],
	inheritance_str: string,
	additional_info_html: string,
	called_at?: string[]
	locs?: Loc[]
}

interface FunctionRelationship {
	caller_id: string
	callee_id: string
}

interface BooleanHashmap {
    [key: string]: boolean;  // You can replace 'any' with a specific type if you know the value type.
}

interface StringHashmap {
    [key: string]: string;  // You can replace 'any' with a specific type if you know the value type.
}


interface RelatedCallstacksHashmap {
    [key: string]: number[];  // You can replace 'any' with a specific type if you know the value type.
}

interface CallstacksEdgeColorsHashmap {
	[key: string]: string;  // You can replace 'any' with a specific type if you know the value type.
}


interface ScopeDefinitionsHashmap {
    [key: string]: ScopeDefinition;  // You can replace 'any' with a specific type if you know the value type.
}

interface funcStateVarReadWrittenMappingHashmap {
	[key: string]: string[];  // You can replace 'any' with a specific type if you know the value type.
}

interface SourceFilesHashmap {
    [key: string]: string[] | undefined;  // You can replace 'any' with a specific type if you know the value type.
}

interface FiletLineColumnOffsetHashmap {
    [key: string]: number;  
}

interface CallGraphHashmap {
    [key: string]: CallGraph;  // You can replace 'any' with a specific type if you know the value type.
}

export interface CallGraph {
	nodes: (graphNode | graphGroup)[],
	edges: graphEdge[]
}

export interface graphGroup { // scope
	data: {
		id: string,
		label: string
		isParent: boolean
		new_title?: string
		backgroundColor?: string
	}
}

export interface graphNode {
	classes: string,
	data: {
		id: string,
		parent?: string
		title: string,
		content?: string
		new_title?: string
		backgroundColor?: string
		relatedFunctionsHTML?: string
		isCollapsed?: boolean
	}
}

export interface graphEdge {
	data: {
		source: string,
		target: string,
		lineColor?: string
	}
}

export interface FunctionIdObj {
	id: string,
	name: string
}


export interface FilteredFunctionState {
	regexPattern: string,
	excludeRegexPattern: string,
	filteredFunctionIds: string[],
	cntRegexPattern: string, // for searching in function body
	hideReviewedState: "Show Reviewed" | "Hide Reviewed Except In Scope" | "Hide Reviewed" | "In Scope Only"
}

export interface Settings {
	excludedRelatedCallstacks: string[]
	manualFunctionRelationshipPath: string
	showAllFunctions: boolean
	ctnt_uses_gitignore: boolean  // whether to use .gitignore for ctnt
}


// function params
// private getCallstacksGraph(callstacks: number[], cache__key: string = "", return_scopes_only: boolean = false, root_scope_id: string = "", append_related_function_html: boolean = true): CallGraph {
export interface getCallstacksGraphParams {
	callstacks: number[] | string[]
	cache__key?: string   // "" to ignore cache, update to `ignore_cache` | how to handle caching of charts / functions?
	return_scopes_only?: boolean
	seen_relationships?: string[]
	root_scope_id?: string
	append_related_function_html?: boolean
	directional_edges_only?: {
		target_function_id: string
		include_direction: "incoming" | "outgoing" | "both" | null
	} | undefined
}

// private mergeCallstacksIntoGraph(callstacks: number[] | undefined, graph: CallGraph, seen_nodes: string[] = [], seen_edges: string[] = [], return_scopes_only = false, root_scope_id: string = "", override_color: string = "", append_related_function_html: boolean = false) {
export interface mergeCallstacksIntoGraphParams {
	graph: CallGraph
	seen_nodes?: string[]
	seen_edges?: string[]
	callstacksGraphParams: getCallstacksGraphParams
	override_color?: string  // move to getCallstacksGraphParams, update functions
}




type DecorationRange = {
	line: number;
	start: number;
	end: number;
};

type DecorationsData = {
	[filePath: string]: {
		[style: string]: DecorationRange[];
	};
};





interface WorkerResult {
	nodes: graphNode[];
	edges: graphEdge[];
}