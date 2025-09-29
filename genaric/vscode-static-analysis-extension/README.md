# Key Combinations

**Graph**
```
ctrl + scroll wheel 		= zoom
ctrl + click & drag 		= pan

shift + alt + click node 	= remove other nodes not in current node's callstack
alt + click node			= remove other nodes not in current node's callstack
```

**Graph + Links ouside graph**:
```
linked text:
click 				= open file @ location
ctrl + click 		= open file in new tab

🔗:
click 				= set selected function (+ it's scope)
ctrl + click 		= set scope
```

**Links outside graph**:
```
linked text:
alt + click			= navigate to node in graph (last graph interacted)
shift + alt + click	= add node to graph (last graph interacted)
alt + ctrl + click	= show function
```

**Graph**:
```
🔍
click				= search for function text + highlight
ctrl + click		= search (highlight) text

🪢
click 				= (1st click = caller | 2nd click = callee)
ctrl + click		= (1st click = callee | 2nd click = caller)

↑ (arrow up) | ↓ (arrow down)
click 				= go-to next node (caller|callee of current node/function)
ctrl + click		= add caller|callee nodes from current node
alt + click			= remove caller|callee nodes from current node  (temporary - will come back when graph is reset)
shift + alt + click	= remove caller|callee nodes from current node  (must be toggled off for graph to reset, this is a setting on the function)


<node : codeblock>
click 				= expand / collapse code
alt + click			= highlight / remove|reset nodes related to function (based on in-app settings)

<edge>
ctrl + shift		= remove manually mapped edge
```


## Keybinds
```
shift + alt + f 	= set cursor @ search text
alt + f 			= maximize window
ctrl + d			= toggle text highlighting / decoration	
```

# Data + Info

Config + data files are located in:
`.vscode/ext-static-analysis`

`ext-static-analysis/graphs`
- Inheritance graph: `inheritance_graph.json`

Look at example projects [EXAMPLE_REPO](https://google.com) for how data is used in these files.


## Demo

[YOUTUBE VIDEO]()

