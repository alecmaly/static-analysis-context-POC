/* 
    Utility Functions
*/

// Detect when Alt or Shift key is pressed down

function escapeRegExp(text) {
    try {
        new RegExp(text)
        return text
    } catch (e) {
        return text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
    }
}


let textToCopy = ""
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        console.log('Text copied to clipboard');
    } catch (err) {
        console.error('Failed to copy text: ', err);
    }
}

function htmlTextToPlaintext(htmlText) {
    var doc = new DOMParser().parseFromString(htmlText, 'text/html');
    return doc.body.textContent || "";
}

function estimateDimensions(content) {
    // Create a hidden div to measure the content size
    let div = document.createElement('div');
    div.style.position = 'absolute';
    div.style.visibility = 'hidden';
    div.style.width = 'auto';
    div.style.height = 'auto';
    div.innerHTML = content;

    document.body.appendChild(div);

    const dimensions = {
        // width: div.offsetWidth + 75,
        width: div.offsetWidth,
        height: div.offsetHeight
    };

    document.body.removeChild(div);
    return dimensions;
}


function recalculateNodeDimensions(cy, node) {
    node.data().isEntryNode = node.incomers().length === 0
    node.data().isExitNode = node.outgoers().length === 0
    

    const content = generateLabelContent(node.data());
    if (content) {
        const dimensions = estimateDimensions(content);
        node.style('width', dimensions.width);
        node.style('height', dimensions.height);
    }
}

// Create a function to determine the content of the label
function generateLabelContent(data) {
    if (data.isCollapsedChild)
        return ""

    // get border color
    let inputText = document.getElementById('search-textbox').value;
    
    let matches_searchText = false
    let matches_searchText_BackgroundColor = "yellow"
    let matches_searchText_border = `10px solid ${matches_searchText_BackgroundColor}`
    if (inputText) {
        switch (inputText) {
            case "<entry>":
                if (data.isEntryNode) {
                    matches_searchText = true
                }
                break
            case "<exit>":
                if (data.isExitNode) {
                    matches_searchText = true
                }
                break
            default:
                // clean input text for regex (e.x.: * breaks)
                const re = new RegExp(escapeRegExp(inputText), 'i');
                if (re.test(data?.title) || re.test(data?.content)) {
                    matches_searchText = true
                }
                break
        }

    }
     
    // set content
    let prefix = ''
    if (window?.funcStateVarReadWriteMapping && window?.stateVarSelected && data?.id) { prefix = window.funcStateVarReadWriteMapping[`${window.stateVarSelected}~${data.id}`] || '' }

    // insert related relatedFunctionsHTML if exists
    let title = data.title
    let index = data.title?.indexOf('<br>');
    // Check if the period exists to avoid errors
    if (index !== -1 && data.relatedFunctionsHTML) {
        // Insert 'to_insert' after the first period
        title = data.title.slice(0, index) + data.relatedFunctionsHTML + data.title.slice(index);
    }

    let label = `<div class="arrows-container"><span class="arrows"><a class='arrow-up' style='cursor: pointer; text-decoration: none' href='#' value='${data.id}'>&#8593;</a><br><a class='arrow-down' style='cursor: pointer; text-decoration: none' href='#' value='${data.id}'>&#8595;</a></span><span class="text">${(prefix + title || '...')}</span></div>`
    if (data.isCollapsed) {
        return `<pre class="cy-title__p1 custom-hyperlinks" style='border: ${matches_searchText ? matches_searchText_border : ""}; background-color: ${matches_searchText ? matches_searchText_BackgroundColor : ""}'>${label}</pre>`;
    } else {
        return `<pre class="cy-title__p1" style='border: ${matches_searchText ? matches_searchText_border : ""}; background-color: ${matches_searchText ? matches_searchText_BackgroundColor : ""}}'><div class="custom-hyperlinks" style="text-align: center">${label}</div><pre><code>${data.content || '...'}</code></pre></pre>`;
    }
}



/*
    Cytoscapes
*/


let timeoutTimer

let layoutOptions = {
    nodeDimensionsIncludeLabels: true,
    name: document.querySelector('#select-cytoscapes-layout').selectedOptions[0].innerText, // 'elk', // elk | dagre
    rankDir: 'LR', // Left-to-right orientation
    elk: {
        algorithm: 'layered',  // layered | force | 
        'elk.direction': 'RIGHT',
        'nodePlacement.strategy': 'INTERACTIVE',
        // 'elk.layered.spacing.nodeNodeBetweenLayers': 50,
        'elk.layered.nodePlacement.bk.fixedAlignment': 'BALANCED',
        'elk.layered.cycleBreaking.strategy': 'DEPTH_FIRST', // DEPTH_FIRST | GREEDY
        'elk.layered.mergeEdges': true,
        'edgeRouting': 'POLYLINE', // ORTHOGONAL | POLYLINE
        'hierarchyHandling': 'INCLUDE_CHILDREN'
    },
    // nodeSep: 100, // Increase this to spread out nodes horizontally
    // rankSep: 100,  // Increase this to spread out nodes vertically
    // edgeSep: 250,  // Adjust this to affect the spacing of edges

    // nodeSpacing: 5,
    // idealEdgeLength: 10
}

let cytoscape_instances = []
let graph = null
let graph2 = null
function createChart(selector_id, elements) {
    let isAllCollapsed = true;  // default if collaposed
    let maxDepth = 99

    let resizedFromInput = false
    let line_color = "#999"
    let node_background_color = "#F2F2F2"

    // functions
    function insertButtons() {
        // Button to collapse/expand all nodes
        var targetElement = document.getElementById(`${selector_id}-container`);


        // remove old buttons
        let old_buttons = targetElement.querySelectorAll(`button,input`)
        for (let btn of old_buttons) {
            btn.remove()
        }



        let graphTitle = document.createElement('span')
        graphTitle.className = 'graph-title'
        targetElement.insertBefore(graphTitle, targetElement.firstChild)

        let goto_search_term_btn = document.createElement('button');
        goto_search_term_btn.innerText = "Go to Search Term"
        goto_search_term_btn.className = `menu-btn`
        goto_search_term_btn.onclick = (evt) => {
            let search_term = document.querySelector('#search-textbox').value
            //regex
            let nodes = cy.nodes().filter(node => { return (node.data('content') && node.data('content').match(new RegExp(escapeRegExp(search_term), 'i'))) || (node.data('title') && node.data('title').match(new RegExp(escapeRegExp(search_term), 'i'))) })
            showGoToFunctionModal(evt, cy, nodes, "Functions with search term")
        }
        targetElement.insertBefore(goto_search_term_btn, targetElement.firstChild)


        let scope_only_btn = document.createElement('button');
        scope_only_btn.innerText = "Scope Only"
        scope_only_btn.className = `menu-btn`
        scope_only_btn.onclick = (evt) => {
            // build edges for parents
            cy.edges().forEach(e => {
                const source = e.source().data().parent;
                const target = e.target().data().parent;

                if (source && target) {
                    const sourceNode = cy.$id(source);
                    const targetNode = cy.$id(target);

                    if (sourceNode && targetNode) {
                        e.remove();
                        // only add if edge doesn't exist
                        if (!cy.$(`edge[source="${sourceNode.id()}"][target="${targetNode.id()}"]`).length) {
                            cy.add({
                                group: 'edges',
                                data: {
                                    id: `${source}-${target}`,
                                    source: source,
                                    target: target
                                }
                            });
                        }
                    }
                }
            })

            cy.nodes().filter(n => { return !n.data().isParent }).remove()
            
            // for parent nodes, verticle align text in center of node HERE
            cy.nodes().filter(n => { return n.data().isParent }).forEach(node => {
                node.style('text-valign', 'center')
            })
            adjustContainerSizeAndRun(selector_id);
        }
        targetElement.insertBefore(scope_only_btn, targetElement.firstChild)



        // add select with two options: Only Nodes, Callstack
        let filterSearchType = document.createElement('select');
        filterSearchType.id = `${selector_id}-filterSearchType`
        filterSearchType.className = `menu-btn ${selector_id}`
        filterSearchType.options.add(new Option('Callstacks', 'Callstacks'))
        filterSearchType.options.add(new Option('Only Nodes', 'Only Nodes'))
        filterSearchType.options.add(new Option('rm Callstacks', 'rm Callstacks'))
        filterSearchType.options.add(new Option('rm Only Nodes', 'rm Only Nodes'))
        filterSearchType.options[0].selected = true
        targetElement.insertBefore(filterSearchType, targetElement.firstChild)


        let tmp_graph = null
        let prevActionKey = null
        let filterSearchTerm = document.createElement('button');
        filterSearchTerm.innerText = "Filter Graph"
        filterSearchTerm.className = `menu-btn ${selector_id} ${selector_id}-filterSearchTerm`
        filterSearchTerm.addEventListener('click', function(){
            let filterSearchType = document.querySelector(`#${selector_id}-filterSearchType`).value
            let searchTerm = document.querySelector(`#search-textbox`).value

            let filtered_elements
            let rm_filtered_elements
            if (filterSearchType === "rm Only Nodes") {
                rm_filtered_elements = cy.elements().filter(ele => {
                    if (["<entry>", "<exit>"].includes(searchTerm)) {
                        return searchTerm === "<entry>" && !ele.data().isEntryNode || searchTerm === "<exit>" && !ele.data().isExitNode
                    }

                    let regex = new RegExp(escapeRegExp(searchTerm), 'i');
                    return ele.data().content && !ele.data().content.match(regex) && ele.data().title && !ele.data().title.match(regex)   
                })
            } else {
                // for each element, if element title or content matches regex, keep it, otherwise remove it. Then iterate through all kept elements and keep all edges that connect to kept elements            
                filtered_elements = cy.elements().filter(ele => {
                    if (["<entry>", "<exit>"].includes(searchTerm)) {
                        return searchTerm === "<entry>" && ele.data().isEntryNode || searchTerm === "<exit>" && ele.data().isExitNode
                    }
                    
                    let regex = new RegExp(escapeRegExp(searchTerm), 'i');
                    return ele.data().content && ele.data().content.match(regex) || ele.data().title && ele.data().title.match(regex)   
                })
            }


            let action_key = filterSearchType + ";" + searchTerm
            let kept_elements
            if (filterSearchType === 'rm Callstacks') {
                // POC w/ removing callstacks with "auth" function
                if (tmp_graph && prevActionKey === action_key) {
                    // temp graph has been set, restore elements                    
                    cy.elements().remove()
                    cy.add(tmp_graph)

                    adjustContainerSizeAndRun(selector_id);
                    tmp_graph = null
                    return
                }
                tmp_graph = cy.elements()
                
                cy.elements().data('isCollapsedChild', false).data('hidden', true).show()

                
                function filterNodes(nodes, all_related_nodes) {
                    return nodes.filter(node => {
                        let incomers = node.incomers().nodes()
                        let outgoers = node.outgoers().nodes()

                        // if ((node.data().title.includes("💥") || incomers.length === 0) && outgoers.length > 1)
                        //     return false  // keep

                        let non_marked_incomers = incomers.filter(n => { return !all_related_nodes.has(n) })
                        return non_marked_incomers.length === 0  // no non-tainted incomers, all incoming nodes are being deleted, return true (delete)

                        // return incomers.length <= 1 // delete (return true)
                    })
                }

                function getAllRelatedNodes(nodes, seen = new Set()) {
                    // get all elements connected to kept elements recursively
                    let all_related_nodes = nodes
                    for (let node of nodes) {
                        if (seen.has(node)) {
                            continue;
                        }
                        seen.add(node);

                        let incoming_nodes = node.incomers().nodes();
                        all_related_nodes = all_related_nodes.union(incoming_nodes)

                        let outgoing_nodes = filterNodes(node.outgoers().nodes(), all_related_nodes);
                        all_related_nodes = all_related_nodes.union(outgoing_nodes)

                        all_related_nodes = all_related_nodes.union(getAllRelatedNodes(outgoing_nodes, seen))
                        all_related_nodes = all_related_nodes.union(getAllRelatedNodes(incoming_nodes, seen))
                    }
                    return all_related_nodes;
                }

                let nodes_to_remove = filtered_elements
                let before
                do {
                    before = nodes_to_remove.size
                    nodes_to_remove = getAllRelatedNodes(nodes_to_remove)
                } while (before !== nodes_to_remove.size)

                kept_elements = cy.elements().difference(nodes_to_remove)
            } else if (filterSearchType === 'Only Nodes') {
                if (tmp_graph && prevActionKey === action_key) {
                    // temp graph has been set, restore elements                    
                    cy.elements().remove()
                    cy.add(tmp_graph)

                    adjustContainerSizeAndRun(selector_id);
                    tmp_graph = null
                    return
                }
                tmp_graph = cy.elements()
                
                cy.elements().data('isCollapsedChild', false).data('hidden', true).show()

                kept_elements = filtered_elements
            } else if (filterSearchType === 'rm Only Nodes') {
                if (tmp_graph && prevActionKey === action_key) {
                    // temp graph has been set, restore elements                    
                    cy.elements().remove()
                    cy.add(tmp_graph)

                    adjustContainerSizeAndRun(selector_id);
                    tmp_graph = null
                    return
                }
                tmp_graph = cy.elements()
                
                cy.elements().data('isCollapsedChild', false).data('hidden', true).show()

                kept_elements = rm_filtered_elements
            } else if (filterSearchType === 'Callstacks') {
                tmp_graph = null

                // get all elements connected to kept elements recursively
                function getAllRelatedNodes(nodes) {
                    let all_related_nodes = nodes
                    for (let startNode of nodes) {
                        let incoming_nodes = startNode.predecessors().nodes();
                        all_related_nodes = all_related_nodes.union(incoming_nodes)

                        let outgoing_nodes = startNode.successors().nodes();
                        all_related_nodes = all_related_nodes.union(outgoing_nodes)
                    }
                    return all_related_nodes;
                }

                cy.elements().remove()
                cy.add(cy.storedElements).data('isCollapsedChild', false).data('hidden', true).show()

                kept_elements = getAllRelatedNodes(filtered_elements)
            }


            kept_elements.data('hidden', false);
            kept_elements.parents().data('hidden', false)  // keep all parents of connected nodes
            

            // remove all elements that are not connected to kept elements
            cy.nodes().filter(ele => { return ele.data().hidden === true }).remove()

            // remove parents that no longer have children
            if (filterSearchType === 'rm Callstacks') {
                cy.nodes().filter(n => { return !n.data().parent && !n.isParent() }).remove()
            }

            adjustContainerSizeAndRun(selector_id);
            prevActionKey = action_key
        });
        targetElement.insertBefore(filterSearchTerm, targetElement.firstChild)

        // Create the select element
        var select = document.createElement('select');
        select.style.marginRight = '2px'
        select.id = `${selector_id}-branch-visibility`

        // Options to be added
        var options = ['Show All', 'Show Incoming', 'Show Outgoing'];

        // Create and append options using a loop
        options.forEach(function(text) {
            var option = document.createElement('option');
            option.value = text.toLowerCase().replace(' ', '-');
            option.text = text;
            select.appendChild(option);
        });

        // Append the select element to the body
        targetElement.insertBefore(select, targetElement.firstChild)

        let setMaxDepth = document.createElement('input')
        setMaxDepth.id = `${selector_id}-depth-input`
        setMaxDepth.className = `menu-btn ${selector_id}`
        setMaxDepth.type = "number"
        setMaxDepth.value = '99'
        setMaxDepth.style.width = '3em'
        setMaxDepth.onkeyup = (evt) => {
            // reset color highlights / traverse graph?
            maxDepth = evt.target.value
        }
        targetElement.insertBefore(setMaxDepth, targetElement.firstChild)


        let collapseExpandButton = document.createElement('button');
        collapseExpandButton.innerText = isAllCollapsed ? 'Expand All' : 'Collapse All';
        collapseExpandButton.className = `menu-btn ${selector_id}`
        collapseExpandButton.addEventListener('click', function(){
            isAllCollapsed = !isAllCollapsed
            collapseExpandButton.innerHTML = isAllCollapsed ? 'Expand All' : 'Collapse All';

            cy.nodes('[?content]').forEach(node => {
                node.data('isCollapsed', isAllCollapsed);

                // calcualte resized node
                recalculateNodeDimensions(cy, node)
            })

            // reload layout
            adjustContainerSizeAndRun(selector_id)
        });
        // targetElement.appendChild(collapseExpandButton) // first element must be appended as container is empty
        targetElement.insertBefore(collapseExpandButton, targetElement.firstChild)

        let toggleLayoutButton = document.createElement('button')
        toggleLayoutButton.className = `menu-btn ${selector_id}`
        toggleLayoutButton.innerText = "Toggle Layout"
        toggleLayoutButton.onclick = () => {
            layoutOptions['rankDir'] = layoutOptions['rankDir'] === "LR" ? "TB" : "LR"
            layoutOptions.elk['elk.direction'] = layoutOptions.elk['elk.direction'] === "RIGHT" ? "DOWN" : "RIGHT"
            adjustContainerSizeAndRun(selector_id)
        }
        targetElement.insertBefore(toggleLayoutButton, targetElement.firstChild)


        let resetGraphButton = document.createElement('button');
        resetGraphButton.id = `reset-graph-${selector_id}`
        resetGraphButton.innerText = "Reset Graph"
        resetGraphButton.className = `menu-btn ${selector_id}`
        resetGraphButton.addEventListener('click', function(){
            window.toDelete = false
            tmp_graph = null // reset temp graph for filtering nodes
            cy.elements().remove()
            cy.add(cy.storedElements).data('isCollapsedChild', false).show()

            cy.nodes().filter(n => { return n.data().isParent }).forEach(node => {
                node.style('text-valign', 'top')  // reset parent text alignment to default (top)
            })
            
            cy.elements().style({
                'background-color': node_background_color, // Replace with your default node color
                'line-color': line_color, // Replace with your default line color
                'opacity': 1 // Reduced opacity for non-highlighted elements
            });
            
            // reset background color on parents
            cy.nodes()
                .forEach(node => {
                    if (node.data('backgroundColor'))
                        node.style('background-color', node.data('backgroundColor'))
                })
            
            adjustContainerSizeAndRun(selector_id);
            last_node_clicked = null
        });
        targetElement.insertBefore(resetGraphButton, targetElement.firstChild)

        
        let loadGraphButton = document.createElement('button');
        loadGraphButton.innerText = "Load"
        loadGraphButton.className = `menu-btn ${selector_id}`
        loadGraphButton.addEventListener('click', function(){
            // cy.elements()
            // send to vscode
            vscode.postMessage({
                command: "load_graph",
                graph_id: selector_id
            })

            // add file 
        });
        targetElement.insertBefore(loadGraphButton, targetElement.firstChild)

        let saveGraphButton = document.createElement('button');
        saveGraphButton.innerText = "Save"
        saveGraphButton.className = `menu-btn ${selector_id}`
        saveGraphButton.addEventListener('click', function(evt){
            console.log(cy)

            vscode.postMessage({
                command: "save_graph",
                content: JSON.stringify(cy.elements().jsons())
            })


            // last_node_clicked = null
        });
        targetElement.insertBefore(saveGraphButton, targetElement.firstChild)

        let setLayoutOptions = document.createElement('input')
        setLayoutOptions.id = `${selector_id}-setLayoutOptions`
        setLayoutOptions.className = `menu-btn ${selector_id}`
        setLayoutOptions.value = "0,0,0"
        setLayoutOptions.title = "nodeSep, edgeSep, rankSep"
        setLayoutOptions.style.maxWidth = '4em'
        setLayoutOptions.onchange = (evt) => {
            let vals = evt.target.value
            let [nodeSep, edgeSep, rankSep] = vals.split(",")

            nodeSep === '0' ? delete layoutOptions.nodeSep : layoutOptions.nodeSep = nodeSep
            edgeSep === '0' ? delete layoutOptions.edgeSep : layoutOptions.edgeSep = edgeSep
            rankSep === '0' ? delete layoutOptions.rankSep : layoutOptions.rankSep = rankSep

            // set elk settings
            nodeSep === '0' ? delete layoutOptions.elk['elk.layered.spacing.nodeNode'] : layoutOptions.elk['elk.layered.spacing.nodeNode'] = nodeSep
            edgeSep === '0' ? delete layoutOptions.elk['elk.layered.spacing.edgeEdge'] : layoutOptions.elk['elk.layered.spacing.edgeEdge'] = edgeSep
            edgeSep === '0' ? delete layoutOptions.elk['elk.layered.spacing.edgeNode'] : layoutOptions.elk['elk.layered.spacing.edgeNode'] = edgeSep
            rankSep === '0' ? delete layoutOptions.elk['elk.layered.spacing.layerLayer'] : layoutOptions.elk['elk.layered.spacing.layerLayer'] = rankSep
            
            console.log(layoutOptions)
            adjustContainerSizeAndRun(selector_id)
        }
        targetElement.insertBefore(setLayoutOptions, targetElement.firstChild)

        let setHeightInput = document.createElement('input')
        setHeightInput.id = `${selector_id}-height-input`
        setHeightInput.className = `menu-btn ${selector_id}`
        setHeightInput.type = "number"
        setHeightInput.step = 1
        setHeightInput.style.maxWidth = '3em'
        setHeightInput.onkeyup = (evt) => {
            document.getElementById(selector_id).style.height = `${evt.target.value}vh`;
            resizedFromInput = true
            adjustContainerSize(cy.layout(layoutOptions))
        }
        targetElement.insertBefore(setHeightInput, targetElement.firstChild)

        let clearClipboardBtn = document.createElement('button')
        clearClipboardBtn.className = `menu-btn ${selector_id}`
        clearClipboardBtn.innerText = "Clear Clipboard"
        clearClipboardBtn.onclick = () => {
            textToCopy = ""
            copyToClipboard("")
        }
        targetElement.insertBefore(clearClipboardBtn, targetElement.firstChild)

        let copyAllBtn = document.createElement('button')
        copyAllBtn.className = `menu-btn ${selector_id}`
        copyAllBtn.innerText = "Copy All"
        copyAllBtn.onclick = () => {
            textToCopy_before = textToCopy
            textToCopy = ""
            cy.nodes('[?content]').forEach(node => {
                textToCopy += node.data('isCollapsed') ? htmlTextToPlaintext(node.data('title')) + "\n" : node.data('content').replaceAll("<br>", "\n") + "\n\n"
            })

            copyToClipboard(textToCopy)
            textToCopy = textToCopy_before
        }
        targetElement.insertBefore(copyAllBtn, targetElement.firstChild)

        let compareGraphsBtn = document.createElement('button')
        compareGraphsBtn.className = `menu-btn ${selector_id}`
        compareGraphsBtn.innerText = graph ? "Compare Graphs (1)" : "Compare Graphs"
        compareGraphsBtn.onclick = () => {
            if (!graph) {
                graph = cy.elements()
                compareGraphsBtn.innerText = "Compare Graphs (1)"
                return
            } 
            
            if (graph && !graph2) {
                graph2 = cy.elements()
                // let in_first_graph_only = graph.filter(node => { return !cy.elements().contains(node) })
                // include parents
                let nodes_in_first_graph_only = graph.nodes().filter(node => { return node.isParent() || !cy.nodes().contains(node) })

                // let in_second_graph_only = cy.elements().filter(node => { return !graph.contains(node) })
                let nodes_in_second_graph_only = cy.nodes().filter(node => { return node.isParent() || !graph.nodes().contains(node)  })

                // add parents
                // remove edges with no source or target
                let graph1_edges_to_keep = graph.edges().filter(function(ele){
                    return nodes_in_first_graph_only.contains(ele.source()) && nodes_in_first_graph_only.contains(ele.target())
                });
                
                let in_first_graph_only = nodes_in_first_graph_only
                                            // .filter(n=>{ 
                                            //     // if (n.isParent() && !nodes_in_first_graph_only.contains(n.children())) 
                                            //     // contains any single child
                                            //     if (n.isParent() && n.children().filter(c => nodes_in_first_graph_only.contains(c)).length > 0)
                                            //         return false
                                            //     return true 
                                            // })
                                            .union(graph1_edges_to_keep)

                  
                // Remove these edges
                let graph2_edges_to_keep = cy.edges().filter(function(ele){
                    return nodes_in_second_graph_only.contains(ele.source()) && nodes_in_second_graph_only.contains(ele.target())
                });

                let in_second_graph_only = nodes_in_second_graph_only
                                            // .filter(n=>{ 
                                            //     // if (n.isParent() && !nodes_in_second_graph_only.contains(n.children())) 
                                            //     // contains any single child
                                            //     if (n.isParent() && n.children().filter(c => nodes_in_second_graph_only.contains(c)).length > 0)
                                            //         return false
                                            //     return true 
                                            // })
                                            .union(graph2_edges_to_keep)


                // add g1 and g2 buttons to toggle graphs
                let g1 = document.createElement('button')
                g1.id = "g1"
                g1.innerText = "g1"
                g1.onclick = () => {
                    cy.elements().remove()
                    cy.add(in_first_graph_only)
                    cy.nodes('[?content]').forEach(node => {
                        // calcualte resized node
                        recalculateNodeDimensions(cy, node)
                    })
                    adjustContainerSizeAndRun(selector_id);
                    // addEventListeners(targetElement)
                }
                
                let g2 = document.createElement('button')
                g2.id = "g2"
                g2.innerText = "g2"
                g2.onclick = () => {
                    cy.elements().remove()
                    cy.add(in_second_graph_only)
                    cy.nodes('[?content]').forEach(node => {
                        // calcualte resized node
                        recalculateNodeDimensions(cy, node)
                    })
                    adjustContainerSizeAndRun(selector_id);
                    // addEventListeners(targetElement)
                } 
                
                targetElement.insertBefore(g2, targetElement.firstChild)
                targetElement.insertBefore(g1, targetElement.firstChild)
                return
            }

            if (graph && graph2) {
                // reset
                graph = null
                graph2 = null
                compareGraphsBtn.innerText = "Compare Graphs"
                // remove g1 and g2 buttons
                targetElement.querySelector('#g1').remove()
                targetElement.querySelector('#g2').remove()
                document.querySelector(`#reset-graph-${selector_id}`).click()

                return
            }

        }
        targetElement.insertBefore(compareGraphsBtn, targetElement.firstChild)
        
        window.toDelete = false
        let toggleBlankNodesBtn = document.createElement('button')
        toggleBlankNodesBtn.className = `menu-btn ${selector_id}`
        toggleBlankNodesBtn.innerText = "Remove blank nodes"
        toggleBlankNodesBtn.onclick = () => {
            let nodes_to_delete = cy.nodes().filter(node => {
                if (node.data('isParent')) return false // don't delete parents
                if (!node.data('content') || node.data('content').split("\n").length <= 1) {
                    return true // mark for deletion
                }
                return false // keep node
            })

            if (!window.toDelete) {
                // just color the nodes to delete
                nodes_to_delete.forEach(node => {
                    node.style({
                        'border-color': 'red',
                        'border-width': 4,
                        'border-opacity': 1
                    });
                })
                window.toDelete = true
                return
            }

            nodes_to_delete.forEach(node => {
                node.remove()
            })

            // remove nodes that are parents and had all children removed
            cy.nodes().forEach(node => {
                if (node.data('isParent') && node.children().length === 0) {
                    node.remove()
                }
            })

            adjustContainerSizeAndRun(selector_id)
        }
        targetElement.insertBefore(toggleBlankNodesBtn, targetElement.firstChild)
    }    

    function configureResizeListener() {
        const divElement = document.getElementById(selector_id);
        let resizeTimer;
        let resizeTimerMs = 25
        
        const onDivResized = () => {
            // Clear any existing timers
            if (resizeTimer) {
                clearTimeout(resizeTimer);
            }
        
            // Start a new timer
            resizeTimer = setTimeout(() => {
                if (resizedFromInput) {
                    // if resized from input box, do nothing (already resized based on user input)
                    resizedFromInput = false
                    return
                }

                adjustContainerSizeAndRun(selector_id)
            }, resizeTimerMs);
        };
        
        const resizeObserver = new ResizeObserver(onDivResized);
        resizeObserver.observe(divElement);
    }

    // main
    cytoscape.use(cytoscape.use(cytoscapeElk))
    const cy = cytoscape({
        container: document.getElementById(selector_id),
        elements: elements,
        style: [{
            selector: 'node',
            style: {
                'background-color': node_background_color,
                'text-wrap': 'wrap',
                'text-valign': 'top',
                'shape': 'rectangle',
                'text-background-opacity': .333,
                'text-background-color': '#F2F2F2',
                'text-background-shape': 'roundrectangle',
                'padding': '10px',
                'text-margin-y': '10px'
            }
        },
        {
            selector: 'node[?content]',
            style: {
                // 'content': 'data(content)',
                'background-color': node_background_color  // override background if in data()
            }
        }, 
        {
            selector: 'node[!content]',
            style: {
                'content': 'data(label)',
            }
        }, 
        {
            selector: 'node:parent',
            style: {
                'background-opacity': 0.333,
                'padding': '20px',
                
                'background-color': '#f5f2f0',
                'color': 'black', // text color
                'text-outline-width': 5,
                'text-outline-color': '#888', // text outline color
            }
        }, 
        {
            selector: 'node[backgroundColor]',
            style: {
                'background-color': 'data(backgroundColor)'  // override background if in data()
            }
        },
        {
            selector: 'edge',
            style: {
                'width': 3,
                'line-color': line_color,
                'target-arrow-color': '#999',
                'target-arrow-shape': 'triangle',
                'curve-style': 'unbundled-bezier',
                'target-distance-from-node': 10,
                'arrow-scale': 1.5
            }
        }, 
        {
            selector: 'edge[lineColor]',
            style: {
                'line-color': 'data(lineColor)'  // override background if in data()
            }
        }
    ],
        zoomingEnabled: true, 
        userZoomingEnabled: false, 
        wheelSensitivity: 0.1, 
        layout: layoutOptions
    });



    cy.nodeHtmlLabel([{
        query: '.l1',
        valign: "center",
        halign: "center",
        valignBox: "center",
        halignBox: "center",
        tpl: generateLabelContent // Use the function instead of a fixed template
    }], { 
        enablePointerEvents: true 
    });



    // making collapsable

    
    cy.container().addEventListener('mouseenter', function(evt) {
        window.focus()
    })

    let ele = document.getElementById(cy.container().id)
    ele.addEventListener('wheel', function(event) {
        console.log("wheeling")
        if (!rightMouseButtonPressed) return
        event.preventDefault(); // Prevent the default scroll behavior
    
        var zoomFactor = 0.075; // Determines how much the graph zooms
        var zoom = cy.zoom();
        var newZoom = event.deltaY > 0 ? zoom - zoomFactor : zoom + zoomFactor; // Zoom in or out
    
        // Set new zoom, ensuring it's within allowed bounds
        cy.zoom({
            level: newZoom,
            renderedPosition: { x: event.offsetX, y: event.offsetY } // Zoom at the point of the cursor
        });
    });

    // Cytoscapes triggers re-render on click when binding to 'tap' event (below)
    // This will track which element we clicked before the re-render
    let originalClickEvent
    cy.on('mousedown', 'node', function(evt) {
        originalClickEvent = evt.originalEvent
    })


    cy.on('tap', 'edge', function(evt){
        // if ctrl and shift held down
        if (evt.originalEvent.ctrlKey && evt.originalEvent.shiftKey) {
            // remove edge
            vscode.postMessage({
                command: "remove_manually_mapped_relationship",
                caller_id: evt.target.data().source,
                callee_id: evt.target.data().target,
            })       

            return
        }

        let f_id = !evt.originalEvent.ctrlKey ? evt.target.data().target : evt.target.data().source
        focusCytoscapesNode(cy, f_id)
    })
    
    // Click event to collapse/expand node on click
    let last_node_clicked
    cy.on('tap', 'node', function(evt){
        let node = evt.target;

        // `originalClickEvent` comes from 'mousedown' event, state of node before re-render

        // Check if the event target is an anchor tag
        if (originalClickEvent && originalClickEvent.target && 
                (
                originalClickEvent.target.tagName === 'A' ||
                originalClickEvent.target.tagName === 'MARK' && originalClickEvent.target?.parentElement.tagName === 'A'
                )
            ) {
            // Allow default behavior for the anchor tag
            handleAnchorClick(originalClickEvent, cy)
            evt.preventDefault()
            return;
        }

        if (originalClickEvent && originalClickEvent.target && 
            (
            originalClickEvent.target.tagName === 'SPAN' && originalClickEvent.target.getAttribute('search_regex') ||
            originalClickEvent.target.tagName === 'MARK' && originalClickEvent.target?.parentElement.tagName === 'SPAN' && originalClickEvent.target.parentElement.getAttribute('search_regex')
            )
        ) {            
            // Allow default behavior for the anchor tag
            handleSearchScopeClick(originalClickEvent) 
            evt.preventDefault()
            return;
        }

        if (originalClickEvent && originalClickEvent.target && 
            (
            originalClickEvent.target.tagName === 'SPAN' && originalClickEvent.target.getAttribute('value') ||
            originalClickEvent.target.tagName === 'MARK' && originalClickEvent.target?.parentElement.tagName === 'SPAN' && originalClickEvent.target.parentElement.getAttribute('value')
            )
        ) {
            let f_id = originalClickEvent.target.getAttribute('value') || originalClickEvent.target.parentElement.getAttribute('value')
            // Allow default behavior for the anchor tag
            main_module.joinFunctions(f_id, originalClickEvent.ctrlKey)
            evt.preventDefault()
            return;
        }

        

        

        // Check if Alt or Shift key is pressed
        let isAltPressed = evt.originalEvent.altKey;
        let isShiftPressed = evt.originalEvent.shiftKey;
        let isCtrlPressed = evt.originalEvent.ctrlKey; // holding ctrl will allow zoom + panning

        if (isCtrlPressed && isAltPressed && isShiftPressed) {
            main_module.setScope(null)
            return
        }


        if (isShiftPressed && isCtrlPressed) {
            evt.preventDefault()
            evt.stopPropagation()
            node.data('hidden', true)
            node.remove()

            main_module.setScope(null)
            return
        }

        if(isShiftPressed && !isAltPressed) { // shift pressed but ctrl not pressed & alt is also not pressed
            evt.preventDefault()
            evt.stopPropagation()
            textToCopy += node.data().isCollapsed ? htmlTextToPlaintext(node.data('title')) + "\n" : node.data('content').replaceAll("<br>", "\n") + "\n\n" 
            copyToClipboard(textToCopy)
            return
        }
        
        if(isAltPressed) {
            evt.preventDefault()
            evt.stopPropagation()

            let removeHiddenElements = !isShiftPressed

            // unhiglight all6

            // need to readd to reset colors?
            // ISSUE: re-adds custom removed nodes
            if (removeHiddenElements) {
                // add elements back if current mode is to remove elements
                cy.add(cy.storedElements).data('hidden', false)
            }
            
            // reset colors
            cy.elements().style({
                'background-color': node_background_color, // Replace with your default node color
                'line-color': line_color, // Replace with your default line color
                'opacity': 1 // Reduced opacity for non-highlighted elements
            });

            // reset colors
            cy.nodes().forEach(ele => {
                let backgroundColor = ele.data('backgroundColor') || node_background_color
                ele.style({
                    'background-color': backgroundColor,
                    'line-color': line_color,
                    'opacity': 1
                })
            })
            cy.edges().forEach(edge => {
                let lineColor = edge.data('lineColor') || line_color
                edge.style({
                    'line-color': lineColor,
                    'opacity': 1
                })
            })
            
            
            
            if (last_node_clicked === node) {
                last_node_clicked = null
                if (removeHiddenElements) {
                    adjustContainerSizeAndRun(selector_id);
                }
                return
            }

            // changes state of nodes, adds 'hidden' attribute
            highlightAndMarkPathsToAndFromNode(node);
            
            // remove marked nodes
            if (removeHiddenElements) {
                // add all elements back (will override manual removal of nodes | shift + ctrl + click|)
                cy.nodes().filter(ele => { return ele.data().hidden }).remove()
                adjustContainerSizeAndRun(selector_id);  // Notify Cytoscape that its container size has changed
            }

            last_node_clicked = node
            return
        }

        if (isCtrlPressed) {
            if (node.children().length) {
                const root = document.querySelector('#scope-detail')

                root.scrollTo({ top: 0 }); // reset scroll to top

                const target = Array.from(root.querySelectorAll('h2')).find(ele => { return ele.innerText === "Functions" })
                const headerOffset = 100; // height of your fixed header in pixels
                const elementPosition = root.getBoundingClientRect().top;

                const containerRect = root.getBoundingClientRect();

                // Get target's bounding rectangle relative to the viewport
                const targetRect = target.getBoundingClientRect();

                // Calculate the target's position relative to the container's scroll
                const offsetPosition = targetRect.top - containerRect.top + target.scrollTop - headerOffset;


                root.scrollTo({
                    top: offsetPosition,
                    behavior: 'smooth'
                });
            }
            return
        }
                    

        // default action, collapse
        node.data('isCollapsed', !node.data('isCollapsed'))

        // if parent node, hide all children
        if (node.data('isCollapsed')) {
            node.children().hide()
            node.children().data('isCollapsedChild', true)
        } else {
            node.children().show()
            node.children().data('isCollapsedChild', false)
        }

        
        recalculateNodeDimensions(cy, node)

        // reload layout
        // adjustContainerSizeAndRun(selector_id)
    });


    function highlightAndMarkPathsToAndFromNode(node) {
        let visitedNodes = new Set(); // To keep track of visited nodes
    
        function findAllAncestors(node) {
            let ancestors = [];
            
            function findParents(currentNode) {
                let parents = currentNode.parents();
                if (parents.nonempty()) {
                ancestors = ancestors.concat(parents.toArray());
                parents.forEach(findParents);
                }
            }
            
            findParents(node);
            return ancestors;
        }
        
        function traverseGraph(currentNode, mode = null, currentDepth = 0) {
            if (currentDepth > maxDepth)
                return

            // don't process current node as we will revisit for traversing up & down (worth performance hit of re-styling single node)
            if (visitedNodes.has(currentNode.id()) && currentNode.id() !== node.id()) {
                currentNode.style('background-color', '#82CDA8')  // revisited nodes will be green
                return; // Avoid revisiting nodes
            }
    
            visitedNodes.add(currentNode.id()); // Mark current node as visited

            // Highlight current node and its connected edges

            if (currentNode == node)
                currentNode.style('background-color', "#FFD132");
            
            
            let directlyConnectedNodes
            let directlyConnectedEdges
            if (mode === 'traveling_down') {
                directlyConnectedNodes = currentNode.outgoers().nodes()
                directlyConnectedEdges = currentNode.outgoers().edges()
            } else if (mode === "traveling_up") {
                directlyConnectedNodes = currentNode.incomers().nodes()
                directlyConnectedEdges = currentNode.incomers().edges()
            }

            let branch_options = document.querySelector(`#${selector_id}-branch-visibility`).selectedOptions[0].innerText
            if (branch_options === "Show Incoming" && mode === "traveling_down" || branch_options === "Show Outgoing" && mode === "traveling_up") {
                // hide paths incoming / outgoing depending on dropdown setting
                directlyConnectedNodes.data('hidden', true)
            } else {
                currentNode.data('hidden', false)
                // update parent
                for (let a of findAllAncestors(currentNode)) {
                    a.data('hidden', false)
                }


                if (currentNode !== node)
                    currentNode.style('background-color', mode == 'traveling_down' ? '#ff8266' : "#00A8CC");

                directlyConnectedEdges.style({
                    'line-color': mode == 'traveling_down' ? '#ff8266' : "#00A8CC",
                    'opacity': 1
                });
            }
            


    
            // Recursively traverse connected nodes
            directlyConnectedNodes.each(function (ele) {
                traverseGraph(ele, mode, currentDepth + 1);
            })
        }
    
        cy.nodes().data('hidden', true)
    
        // Start traversal from the clicked node
        traverseGraph(node, 'traveling_down');
        traverseGraph(node, 'traveling_up');
    }



    // changed from events: 'viewport data mouseup dragfree'
    cy.on('render', function(evt) {
        clearTimeout(timeoutTimer);
        timeoutTimer = setTimeout(() => { main_module.highlightSearchRegex() }, main_module.CONSTANTS.doneTypingInterval);  // reset highlights (timeout needed, race condition with rendering. Should perhaps tie to event instead.)
    });

    
    // Listen for drag events and pan if shift is held (without alt or ctrl)
    cy.on('mousemove', function(event) {
        let SCALE_FACTOR = 1.5
        main_module.last_graph_interacted = cy
        if ((event.originalEvent.ctrlKey && !event.originalEvent.altkey && !event.originalEvent.shiftKey) || rightMouseButtonPressed) {
            // Calculate the movement delta
            let panDelta = { x: event.originalEvent.movementX * SCALE_FACTOR, y: event.originalEvent.movementY * SCALE_FACTOR };
            // Adjust the pan based on the delta
            cy.panBy(panDelta);
        }
    });


    // cy.on('layoutstop', function(evt) {
    //     console.log(`Stopped ${selector_id}`)        
    // })

    // resize on first load
    cy.nodes().forEach(node => {
        node.data('isCollapsed', !node.data('isParent') && isAllCollapsed) // do not collapse parents
        recalculateNodeDimensions(cy, node)
    });



    insertButtons()
    configureResizeListener()

    cy.storedElements = cy.elements()
    
    cytoscape_instances.push(cy)
}

function clearCytoscapeInstances(type = "all") {
    if (type === "scope") {
        cytoscape_instances = cytoscape_instances.filter(instance => { return instance.container().id !== 'cy-scope' })
    } else if (type === "function") {
        cytoscape_instances = cytoscape_instances.filter(instance => { return instance.container().id === 'cy-scope' })
    } else if (type === "all") {
        cytoscape_instances = []
    }
    // remove all instances that are not the scope graph
}

function reloadGraphs() {
    for (let cy of cytoscape_instances) {
        // recalculateNodeDimensions(cy, node)
        // cy.resize()
        cy.nodes().forEach(node => {

            // calcualte resized node
            recalculateNodeDimensions(cy, node)
        })
        // cy.layout(layoutOptions).run()
        // cy.elements().render()
    }
}

function adjustContainerSizeAndRun(selector_id) {
    let cy = cytoscape_instances.find(i => { return i.container().id === selector_id })
    let layout = cy.layout(layoutOptions)
    function adjustContainerSize() {
        let boundingBox = cy.elements().boundingBox();
        let newHeight = boundingBox.h + 200;  // adding 50 as a buffer
        let newHeightVh = pxToVh(newHeight)
        // Adjust based on your requirements:
        // if (newHeight < 500) {  // setting a maximum height for small graphs
        document.getElementById(selector_id).style.height = `${newHeightVh}vh`;
        cy.resize();  // Notify Cytoscape that its container size has changed
        // }

        let height_input = document.getElementById(`${selector_id}-height-input`)
        if (height_input) {
            height_input.value = newHeightVh
        }
    }

    layout.on('layoutstop', function() {
        adjustContainerSize();
        clearTimeout(timeoutTimer);
        timeoutTimer = setTimeout(() => { main_module.highlightSearchRegex() }, main_module.CONSTANTS.doneTypingInterval);  // reset highlights (timeout needed, race condition with rendering. Should perhaps tie to event instead.)    
    });
    
    layout.run()
}

function setGraph(selector, graph, focus_node_fId = null, graph_title = "") {
    let graph_instance = cytoscape_instances.find(i => { return i.container().id === selector })
    
    // set title of graph
    document.querySelector(`#${graph_instance.container().id}-container`).querySelector('.graph-title').innerText = graph_title

    graph_instance.elements().remove()
    graph_instance.add(graph)

    graph_instance.nodes().forEach(node => {

        // calcualte resized node
        recalculateNodeDimensions(graph_instance, node)
    })

    // reload layout
    adjustContainerSizeAndRun(selector)

    graph_instance.storedElements = graph_instance.elements()
    
    if (focus_node_fId) {
        focusCytoscapesNode(graph_instance, focus_node_fId)
    }
}


function pxToVh(pxValue) {
    let viewportHeight = window.innerHeight;
    let vhValue = (pxValue / viewportHeight) * 100;
    return vhValue;  // returns the value in vh units
}


window.addEventListener('keyup', function(e) {
    if (e.key === "Escape") {
        document.querySelector("#popup").style.display = "none";
    }
    
    for (let cy of cytoscape_instances) {
        cy.userZoomingEnabled(false);
    }

});

window.addEventListener('keydown', function(e) {
    if (e.ctrlKey) {
        for (let cy of cytoscape_instances) {
            cy.userZoomingEnabled(true);
        }
    }
});


let rightMouseButtonPressed = false;
window.addEventListener('mousedown', function(e) {
    // Right mouse button has a button code of 2
    if (e.button === 2) {
        rightMouseButtonPressed = true;
    }
});

window.addEventListener('mouseup', function(e) {
    if (e.button === 2) {
        rightMouseButtonPressed = false;
    }
});




