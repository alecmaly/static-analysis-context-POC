// @ts-nocheck
// This script will be run within the webview itself
// It cannot access the main VS Code APIs directly.

// open file links
// https://github.com/Microsoft/vscode/issues/63073

const vscode = acquireVsCodeApi();

function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
}

// Decompress the byte array using Pako
function decompressHexString(hexString) {
    try {
        const byteArray = hexToBytes(hexString); // Convert hex to bytes
        const decompressed = pako.inflate(byteArray); // Decompress using Pako
        return new TextDecoder().decode(decompressed); // Convert bytes to string
    } catch (e) {
        // reutrn original string if error
        return hexString
    }
}

function escapeRegExp(text) {
    try {
        new RegExp(text)
        return textChangeRangeNewSpan
    } catch {
        return text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
    }
}


function waitForElement(selector, callback) {
    if (document.querySelector(selector)) {
        callback();
    } else {
        setTimeout(function() {
            waitForElement(selector, callback);
        }, 100);
    }
}

let copilotChatWindowOpen = false
function openCopilotChatPrompt(message = "test prompt") {
    if (copilotChatWindowOpen) {
        // if already open, just focus it
        document.querySelector('#copilot-chat-prompt').focus()
        return
    }
    copilotChatWindowOpen = true

    // create container
    let container = document.createElement('div')
    container.style.position = "fixed"
    container.style.top = "50px"
    container.style.left = "50%"
    container.style.transform = "translateX(-50%)"
    container.style.width = "80%"
    container.style.zIndex = "1000"
    container.style.backgroundColor = "white"
    container.style.border = "2px solid #ccc"
    container.style.borderRadius = "8px"
    container.style.padding = "20px"
    container.style.boxShadow = "0 4px 8px rgba(0,0,0,0.1)"
    
    // Create header for dragging
    let header = document.createElement('div')
    header.style.cursor = "move"
    header.style.height = "20px"
    header.style.backgroundColor = "#f1f1f1"
    header.style.marginBottom = "10px"
    header.style.borderRadius = "4px"
    header.textContent = "Drag here to move"
    header.style.textAlign = "center"
    header.style.lineHeight = "20px"
    header.style.fontSize = "12px"
    header.style.color = "#666"
    
    // Make only header draggable
    let pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;
    let isDragging = false;
    header.onmousedown = dragMouseDown;
    
    function dragMouseDown(e) {
        e = e || window.event;
        e.preventDefault();
        
        if (!isDragging) {
            // On first drag, calculate the actual position and remove transform
            const rect = container.getBoundingClientRect();
            container.style.left = rect.left + "px";
            container.style.top = rect.top + "px";
            container.style.transform = "none";
            isDragging = true;
        }
        
        pos3 = e.clientX;
        pos4 = e.clientY;
        document.onmouseup = closeDragElement;
        document.onmousemove = elementDrag;
    }
    
    function elementDrag(e) {
        e = e || window.event;
        e.preventDefault();
        pos1 = pos3 - e.clientX;
        pos2 = pos4 - e.clientY;
        pos3 = e.clientX;
        pos4 = e.clientY;
        container.style.top = (container.offsetTop - pos2) + "px";
        container.style.left = (container.offsetLeft - pos1) + "px";
    }
    
    function closeDragElement() {
        document.onmouseup = null;
        document.onmousemove = null;
        isDragging = false;
    }
    
    container.appendChild(header);
    
    // create textarea with prompt
    const height = window.innerHeight;
    let ctx = document.querySelector('#copilot-ctx').innerText
    let textarea = document.createElement('textarea')
    textarea.id = "copilot-chat-prompt"
    textarea.value = `${ctx}\n\n${message}`
    textarea.style.width = "100%"
    textarea.style.height = `${height * 0.6}px`
    textarea.style.marginBottom = "10px"
    textarea.style.resize = "both"
    
    textarea.addEventListener('input', () => {
        // Auto-resize container based on textarea content
        container.style.height = 'auto';
        container.style.height = Math.min(textarea.scrollHeight + 100, window.innerHeight * 0.8) + 'px';
        container.style.width = Math.min(textarea.scrollWidth + 40, window.innerWidth * 0.9) + 'px';
    });
    
    // Also resize on textarea resize (when user manually resizes)
    new ResizeObserver(() => {
        container.style.height = 'auto';
        container.style.height = Math.min(textarea.scrollHeight + 100, window.innerHeight * 0.8) + 'px';
        container.style.width = Math.min(textarea.scrollWidth + 40, window.innerWidth * 0.9) + 'px';
    }).observe(textarea);
    
    // send button
    let sendBtn = document.createElement('button')
    sendBtn.innerText = "Send to Copilot Chat"
    sendBtn.style.marginRight = "10px"
    sendBtn.onclick = () => {
        vscode.postMessage({command: "send_to_copilot_chat", message: textarea.value})
        document.body.removeChild(container)
        copilotChatWindowOpen = false
    }
    
    // cancel button
    let cancelBtn = document.createElement('button')
    cancelBtn.id = "copilot-chat-cancel-btn"
    cancelBtn.innerText = "Cancel"
    cancelBtn.onclick = () => {
        document.body.removeChild(container)
        copilotChatWindowOpen = false
    }
    
    // add keyboard event listeners
    container.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
            e.preventDefault()
            sendBtn.click()
        } else if (e.key === 'Escape') {
            e.preventDefault()
            cancelBtn.click()
        }
    })
    // add elements to container
    container.appendChild(textarea)
    container.appendChild(sendBtn)
    container.appendChild(cancelBtn)
    
    // add container to body
    document.body.appendChild(container)

    textarea.focus()
}

function focusCytoscapesNode(cy, f_id) {
    let nodes = cy.getElementById(f_id)
    
    cy.animate({
        center: {
            eles: nodes
        },
        zoom: .9 // You can adjust the zoom level as needed
    }, {
        duration: 1000 // Duration of the animation in milliseconds (1 second in this example)
    });

    // if not already yellow
    if (nodes.style('background-color') !== "rgb(255,255,0)") { 
        node_original_color[f_id] = nodes.style('background-color')
    }
    
    nodes.style('background-color', 'yellow')
    setTimeout(() => {
        if (nodes.style('background-color') !== "rgb(255,255,0)") { return } // if not still yellow, then it was changed by another click event
        nodes.style('background-color', node_original_color[f_id])
    }, 2000)

    cy.container().scrollIntoView({behavior: 'smooth', block: 'center'})
}

let isDragging = false
function showGoToFunctionModal(evt, cy, outgoing_nodes, title_text_override = "") {
    // show a popup to select which node to focus on, popup at the mouse position, one click to select
    let popup = document.createElement('div')
    popup.id = "popup"
    popup.style.position = "absolute"
    popup.style.left = evt.pageX + "px"
    popup.style.top = evt.pageY + "px"
    popup.style.backgroundColor = "white"
    popup.style.border = "1px solid black"
    popup.style.padding = "5px"
    popup.style.zIndex = "1000"
    popup.style.display = "block"
    popup.style.color = "black"
    popup.style.cursor = "pointer"

    // make popup draggable
    let pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;
    popup.onmousedown = dragMouseDown;
    function dragMouseDown(e) {
        e = e || window.event;
        e.preventDefault();
        // get the mouse cursor position at startup:
        pos3 = e.clientX;
        pos4 = e.clientY;
        document.onmouseup = closeDragElement;
        // call a function whenever the cursor moves:
        document.onmousemove = elementDrag;
    }

    function elementDrag(e) {
        isDragging = true
        e = e || window.event;
        e.preventDefault();
        // calculate the new cursor position:
        pos1 = pos3 - e.clientX;
        pos2 = pos4 - e.clientY;
        pos3 = e.clientX;
        pos4 = e.clientY;
        // set the element's new position:
        popup.style.top = (popup.offsetTop - pos2) + "px";
        popup.style.left = (popup.offsetLeft - pos1) + "px";
    }

    function closeDragElement() {
        // stop moving when mouse button is released:
        document.onmouseup = null;
        document.onmousemove = null;
    }

        
    let popup_title = document.createElement('h3')
    popup_title.innerText = title_text_override || `Select Node`
    popup.appendChild(popup_title)

    // close x button
    let close_btn = document.createElement('span')
    close_btn.innerText = "X"
    close_btn.style.position = "absolute"
    close_btn.style.fontSize = "2em"
    close_btn.style.right = "10px"
    close_btn.style.color = "red"
    close_btn.style.top = "5px"
    close_btn.style.cursor = "pointer"
    close_btn.onclick = () => {
        popup.style.display = "none"
    }
    popup.appendChild(close_btn)
    

    let search_bar = document.createElement('input')
    search_bar.id = "popup-search-bar"
    search_bar.placeholder = "Search..."
    search_bar.style.width = "100%"
    search_bar.onkeyup = (evt) => {
        let search_term = evt.target.value.toLowerCase()
        let lis = popup_list.querySelectorAll('li')
        lis.forEach(li => {
            if (!search_term || new RegExp(escapeRegExp(search_term), 'i').test(li.innerText)) {
                li.style.display = 'list-item';
            } else {
                li.style.display = 'none';
            }
        })
    }
    popup.appendChild(search_bar)


    let popup_list = document.createElement('ul')
    popup.appendChild(popup_list)

    outgoing_nodes.forEach(node => {
        let li = document.createElement('li')
        li.innerHTML = node.data().title
        li.onclick = () => {
            if (isDragging) {
                return
            }
            
            focusCytoscapesNode(cy, node.id())
            popup.style.display = "none"
        }
        
        // set link background color to default blue for lighter background popup
        Array.from(li.querySelectorAll('a')).forEach(n => { 
            // remove link underline from nodes with data-scope property
            if (n.getAttribute('data-scope')) {
                n.style.textDecoration = "none"
            }     
            n.style.color = 'blue'
            n.style.fontSize = "1.2em"
        })  
        
        popup_list.appendChild(li)
    }
    )
    document.body.appendChild(popup)

    // remove popup on click outside
    setTimeout(() => {
        document.body.onclick = (evt) => {
            if (isDragging) {
                isDragging = false
                return
            }

            if (evt.target.id === "popup-search-bar") {
                evt.target.focus()
                return
            }

            if (evt.target.id !== "popup") {
                popup.style.display = "none"
            }
        }
    }, 250)
}

let node_original_color = {}
function handleAnchorClick(evt, cy = null) {
    evt.preventDefault()
    // let target = evt.target.tagName === "A" ? evt.target : evt.currentTarget
    
    let target = null
    if (evt.target.tagName === "A") {
        target = evt.target
    } else if (evt.target.tagName === "MARK" && evt.target.parentElement && evt.target.parentElement.tagName === "A") {
        target = evt.target.parentElement
    } else {
        target = evt.currentTarget
    }

    if (!target) { return }

    if (cy && target.className === "arrow-up") { 
        let f_id = target.getAttribute('value')
    

        if (evt.ctrlKey) {
            vscode.postMessage({command: "expand_graph_by_function", graph_id: cy.container().id, graph_edges: cy.edges().jsons(), graph_nodes: cy.nodes().jsons(), f_id: f_id, direction: "incoming"});
            return
        }

        // if (evt.shiftKey && evt.altKey) {
        //     vscode.postMessage({
        //         command: "set_hide_callstacks_from_function",
        //         f_id: f_id,
        //         value: null,
        //         direction: "incoming",
        //         graph_id: cy.container().id,
        //         graph_nodes: cy.nodes().jsons(),
        //         graph_edges: cy.edges().jsons()
        //     })
        //     return
        // }

        if (evt.altKey) {
            // remove parent nodes
            parentNode = cy.getElementById(f_id);
            let parentNodes = parentNode.predecessors('node');

            // Find edges connected to the child nodes
            let connectedEdges = parentNodes.connectedEdges();
            
            // Remove both the child nodes and their connected edges
            parentNodes.remove();
            connectedEdges.remove();


            // remove orphined parents
            cy.elements().filter(n => {
                return n.data('isParent') && n.children().length === 0
            }).remove()

            // shift + alt
            if (evt.shiftKey) {
                vscode.postMessage({
                    command: "set_hide_callstacks_from_function",
                    f_id: f_id,
                    value: null,
                    direction: "incoming",
                    graph_id: cy.container().id,
                    graph_nodes: cy.nodes().jsons(),
                    graph_edges: cy.edges().jsons()
                })
            }

            return
        }


        let clicked_node = cy.getElementById(f_id);

        let incoming_nodes = clicked_node.incomers('node')
        if (incoming_nodes.length === 1) {
            focusCytoscapesNode(cy, incoming_nodes.first().id())
        } else if (incoming_nodes.length > 1) {
            showGoToFunctionModal(evt, cy, incoming_nodes, "Select Node: INCOMING")
        }
        return
    }

    if (cy && target.className === "arrow-down") {
        let f_id = target.getAttribute('value')

        if (evt.ctrlKey) {
            vscode.postMessage({command: "expand_graph_by_function", graph_id: cy.container().id, graph_edges: cy.edges().jsons(), graph_nodes: cy.nodes().jsons(), f_id: f_id, direction: "outgoing"});
            return
        }


        // if (evt.shiftKey && evt.altKey) {
        //     vscode.postMessage({
        //         command: "set_hide_callstacks_from_function",
        //         f_id: f_id,
        //         value: null,
        //         direction: "outgoing",
        //         graph_id: cy.container().id,
        //         graph_nodes: cy.nodes().jsons(),
        //         graph_edges: cy.edges().jsons()
        //     })

        //     // remove nodes from graph incoming/outgoing
        //     return
        // }


        if (evt.altKey) {
            // remove child nodes
            parentNode = cy.getElementById(f_id);

            // Find all child nodes
            let childNodes = parentNode.successors('node');
            
            // Find edges connected to the child nodes
            let connectedEdges = childNodes.connectedEdges();
            
            // Remove both the child nodes and their connected edges
            childNodes.remove();
            connectedEdges.remove();

            // remove orphined parents
            cy.elements().filter(n => {
                return n.data('isParent') && n.children().length === 0
            }).remove()            
            
            // shift + alt
            if (evt.shiftKey) {
                vscode.postMessage({
                    command: "set_hide_callstacks_from_function",
                    f_id: f_id,
                    value: null,
                    direction: "outgoing",
                    graph_id: cy.container().id,
                    graph_nodes: cy.nodes().jsons(),
                    graph_edges: cy.edges().jsons()
                })
            }

            return
        }

        
        let clicked_node = cy.getElementById(f_id);

        let outgoing_nodes = clicked_node.outgoers('node')
        if (outgoing_nodes.length === 1) {
            focusCytoscapesNode(cy, outgoing_nodes.first().id())
        } else if (outgoing_nodes.length > 1) {
            showGoToFunctionModal(evt, cy, outgoing_nodes, "Select Node: OUTGOING")
        }
        
        return
    }
    

    

    let href = target.getAttribute('href')
    if (href.startsWith("#")) {
        if (evt.ctrlKey) {
            // get scope
            let scope_id = target.getAttribute("data-scope") || ""
            if (scope_id) {
                main_module.setScope(scope_id)
            }
        } else {
            vscode.postMessage({command: "show_function", function_id: href.slice(1), mode: window.callstacks_graph_mode, include_related_callstacks: window.include_related_callstacks})
        }
    } else if (href.startsWith("scrollTo:")) {
        const [cmd, selector, parents_to_highlight] = href.split(":")
        const element = document.querySelector(selector)
        if (element) {
            element.scrollIntoView({behavior: "smooth", block: "center"})
            
            let parent = element
            for (let i = 0; i < parents_to_highlight; i++) {
                parent = parent.parentElement
            }
            parent.style.backgroundColor = "yellow"
            setTimeout(() => {
                parent.style.backgroundColor = ""
            }, 2000)
        }
        return
    } else if (href.startsWith("file:")) {
        // open function summary
        if (evt.altKey && evt.ctrlKey) {
            let f_id = target.getAttribute('value')
            vscode.postMessage({command: "show_function", function_id: f_id, mode: window.callstacks_graph_mode, include_related_callstacks: window.include_related_callstacks})
            return
        }


        // navigate to node in graph
        if (evt.altKey && !evt.shiftKey) {
            if (!cy) {
                cy = main_module.last_graph_interacted
            }
            // if holding alt, override to navigate to node in graph
            let f_id = target.getAttribute('value')
            let nodes = cy.getElementById(f_id)  // should only match 1 node but cytoscapes seems to return an object with a .length property & .animate() accepts `eles` as an argument
            
            if (nodes.length > 0) {
                /* node found */
                // var position = node.position();
                
                // Animate the viewport to center on the node!=
                focusCytoscapesNode(cy, f_id)
                // highlight node
                // main_module.setHighlight(f_id.split(",")[0])
            }
            return
        }
        
        if (evt.altKey && evt.shiftKey) {
            // add node to graph
            if (!cy) {
                cy = main_module.last_graph_interacted
            }
            let f_id = target.getAttribute('value')
            
            vscode.postMessage({command: "expand_graph_by_function", graph_id: cy.container().id, graph_edges: cy.edges().jsons(), graph_nodes: cy.nodes().jsons(), f_id: f_id, direction: "both"});
            return
        }

        // default: open file
        vscode.postMessage({command: "open", is_ctrl_click: evt.ctrlKey, link: href});
    }
}

function handleSearchScopeClick(evt) {
    let target = null
    if (evt.target.tagName === "SPAN") {
        target = evt.target
    } else if (evt.target.tagName === "MARK" && evt.target.parentElement && evt.target.parentElement.tagName === "SPAN") {
        target = evt.target.parentElement
    } else {
        target = evt.currentTarget
    }

    let func_search_regex = target.getAttribute('search_regex')
    
    if (evt.ctrlKey) {
        func_search_regex_highlight = func_search_regex.replace(/^(\\\.|\^)/, "")
        main_module.setHighlight(func_search_regex_highlight)
        
        // holding ctrl + alt will highlight AND search
        if (!evt.altKey) {
            return
        }
    }

    document.querySelector("#function-selector-textbox").value = func_search_regex
    main_module.searchFuncMode = "identifier"
    main_module.searchFunctions()
}



let main_module = (function () {
    // defaults
    window.callstacks_graph_mode = "Combined"
    window.include_related_callstacks = false

    function scrollToTop() {
        window.scrollTo(0, 0)
        document.querySelector('#function-summary').scrollTo(0, 0)
        document.querySelector('#scope-detail').scrollTo(0, 0)
    }


    function setSelectedStateVar(btn_stateVar) {
        let new_var_name = btn_stateVar.getAttribute('value')?.split('~')[0]
        let var_name = new_var_name !== window.stateVarSelected ? new_var_name : null
        
        let state_var_btn_arr = Array.from(document.querySelector('#scope-detail').querySelectorAll('.setStateVar'))
        let current_index = state_var_btn_arr.findIndex(ele => { return ele === btn_stateVar })

        window.stateVarSelected = var_name
        window.stateVarSelectedIndex = current_index
        vscode.postMessage({ command: "requestFuncStateVarReadWriteMapping" })
        document.querySelector('#selectedStateVar').innerText = var_name ? `StateVar: (${current_index + 1}/${state_var_btn_arr.length}) ${var_name}` : ''

        reloadGraphs()
        setHighlight(var_name)

        // scroll to state graph
        document.querySelector(".cy-scope").scrollIntoView()
    }
    
    // START Window Resizing
    // horizontal
    function configureResizeHandler() {
        var handler = document.querySelector('#resizable-handle');
        var wrapper = handler.closest('.container');
        var boxA = wrapper.querySelector('#function-summary');
        var isHandlerDragging = false;

        document.addEventListener('mousedown', function (e) { // If mousedown event is fired from .handler, toggle flag to true
            if (e.target === handler) {
                isHandlerDragging = true;
            }
        });

        document.addEventListener('mousemove', function (e) { // Don't do anything if dragging flag is false
            if (! isHandlerDragging) {
                return false;
            }

            // Get offset
            var containerOffsetLeft = wrapper.offsetLeft;

            // Get x-coordinate of pointer relative to container
            var pointerRelativeXpos = e.clientX - containerOffsetLeft;

            // Arbitrary minimum width set on box A, otherwise its inner content will collapse to width of 0
            var boxAminWidth = 60;

            // Resize box A
            // * 8px is the left/right spacing between .handler and its inner pseudo-element
            // * Set flex-grow to 0 to prevent it from growing
            boxA.style.width = (Math.max(boxAminWidth, pointerRelativeXpos - 8)) + 'px';
            // boxA.style.flexGrow = 0;
        });

        document.addEventListener('mouseup', function (e) { // Turn off dragging flag when user mouse is up
            isHandlerDragging = false;
        });
    }
    configureResizeHandler()


    // vertical
    let resizeTimer;

    function adjustContainerHeight() {
        const container = document.querySelector('#scope-graph-container');
        const header = document.querySelector('.sticky-header');
        // const functionsList = document.querySelector('.functions-list');
        const decoratorDescription = document.querySelector('#decorator-description');

        let usedHeight = Array.from(document.body.children).reduce((height, child) => {
            if (child === header || child === decoratorDescription) {
                height += child.offsetHeight;
            }
            return height;
        }, 0);
        if (usedHeight > 5) 
            usedHeight += 5
        
        console.log(usedHeight)
        container.style.height = `calc(100vh - ${usedHeight}px)`;
    }

    // function handleResize() { // Clear the existing timer
    //     clearTimeout(resizeTimer);

    //     // Set a new timer
    //     resizeTimer = setTimeout(() => {
    //         adjustContainerHeight();
    //     }, 200);
    // }

    // window.addEventListener('resize', handleResize);
    // END Window Resizing

    window.addEventListener('keyup', function(evt) {
        let isAltPressed = evt.altKey;
        let isShiftPressed = evt.shiftKey;
        let isCtrlPressed = evt.ctrlKey;

        if (isShiftPressed && isAltPressed && evt.key === 'F') {
            evt.preventDefault()
            let input = document.getElementById('search-textbox')
            if (input) {
                input.focus()
                input.select()
            }
        }


        if (isShiftPressed && isAltPressed && evt.key === 'ArrowRight') {
            let state_var_btns = Array.from(document.querySelector('#scope-detail').querySelectorAll('.setStateVar'))
            let next_index = window.stateVarSelectedIndex + 1
            
            if (next_index >= state_var_btns.length) {
                next_index = 0
            }

            setSelectedStateVar(state_var_btns[next_index])
        }

        if (isShiftPressed && isAltPressed && evt.key === 'ArrowLeft') {
            let state_var_btns = Array.from(document.querySelector('#scope-detail').querySelectorAll('.setStateVar'))
            let next_index = window.stateVarSelectedIndex - 1
            
            if (next_index < 0) {
                next_index = state_var_btns.length - 1
            }

            setSelectedStateVar(state_var_btns[next_index])
        }

    })

    vscode.setState({"function_history_ids": [], "function_history_index": 0})

    let typingTimer;
    const doneTypingInterval = 400; // Adjust this value as desired (in milliseconds)


    function GetScopeRegexOfFunc(funcId) {
        let func_name = funcId.replace("[X] ", "").split(" ")[0].split(",")[0]

        if (func_name.includes(".")) {
            return "^" + func_name.split(".").slice(0, -1).join(".") + "\\."
        } else if (func_name.includes("|")) {
            return "^" + func_name.split("|").slice(0, -1).join("|") + "\\|"
        } else {
            return "^" + func_name.split(" ")[0] + " "
        }
    }

    function AddEventListeners(root_node) {
        configureResizeHandler()

        document.querySelector('#select-cytoscapes-layout').addEventListener('change', (evt) => {
            layoutOptions.name = evt.target.selectedOptions[0].innerText
        })

        
        document.querySelector('#select-search-template')?.addEventListener('input', (evt) => {
            if (evt.target.selectedIndex !== 0) {
                let textbox = document.querySelector("#function-selector-textbox")
                let exclude_textbox = document.querySelector("#function-selector-exclude-textbox")
                let regex_before = textbox.value
                let regex_exclude_before = exclude_textbox.value

                let include = evt.target.selectedOptions[0].getAttribute('data-include') || ""
                let exclude = evt.target.selectedOptions[0].getAttribute('data-exclude') || ""
                let highlight = evt.target.selectedOptions[0].getAttribute('data-highlight') || ""
                // document.querySelector("#function-selector-textbox").value = include  
                // do above but handle when include has a quote in it "
                if (highlight) {
                    setHighlight(highlight)
                }

                if (include != "<no_change>")
                    textbox.value = include
                if (exclude != "<no_change>")
                    exclude_textbox.value = exclude

                if (regex_before !== textbox.value || regex_exclude_before !== exclude_textbox.value)
                    window.searchFunc()
            }
            // reset dropdown
            document.querySelector('#select-search-template').selectedIndex = 0
        })


        document.querySelector('#select-search-template-scope')?.addEventListener('change', (evt) => {
            if (evt.target.selectedIndex !== 0) {
                let textbox = document.querySelector("#scope-regex-filter")
                let exclude_textbox = document.querySelector("#scope-regex-exclude-filter")
                let regex_before = textbox.value
                let regex_exclude_before = exclude_textbox.value


                let include = evt.target.selectedOptions[0].getAttribute('data-include') || ""
                let exclude = evt.target.selectedOptions[0].getAttribute('data-exclude') || ""

                if (include != "<no_change>") {
                    textbox.value = include
                    window.scope_filter_regex = include
                }
                if (exclude != "<no_change>") {
                    exclude_textbox.value = exclude
                    window.scope_filter_exclude_regex = exclude
                }

                if (regex_before !== textbox.value || regex_exclude_before !== exclude_textbox.value) 
                    updateScopeHTML(window.scope_filter_regex, window.scope_filter_exclude_regex, window.scope_is_collapsed, window.scope_is_collapsed_2)
            }
            // reset dropdown
            document.querySelector('#select-search-template-scope').selectedIndex = 0
        })



        for (const exec_arbitrary_js_btn of root_node.querySelectorAll('button[value^="exec:"]')) {
            if (exec_arbitrary_js_btn.getAttribute('data-auto') === "true" && exec_arbitrary_js_btn.getAttribute('data-executed') !== "true") {
                let js = atob(exec_arbitrary_js_btn.getAttribute('value').replace("exec:", ""))
                try {
                    eval(js)
                } catch (e) {
                    vscode.postMessage({command: "eval_failure", error: `Error executing JS: ${e}`})
                }
                exec_arbitrary_js_btn.setAttribute('data-executed', 'true')
            }

            exec_arbitrary_js_btn.addEventListener('click', (evt) => {
                let js = atob(evt.target.getAttribute('value').replace("exec:", ""))
                try {
                    eval(js)
                } catch (e) {
                    vscode.postMessage({command: "eval_failure", error: `Error executing JS: ${e}`})
                }
            });
        }
        
        for (const open_doc_btn of root_node.querySelectorAll('button[value^="openfile://"]')) {
            open_doc_btn.addEventListener('click', (evt) => {
                let filename = evt.target.getAttribute('data-filename')
                let content = evt.target.getAttribute('value').replace("openfile://", "")
                vscode.postMessage({command: "content_to_new_file", filename: filename, content: content });
            });
        }

        for (const link of root_node.querySelectorAll('a[href^="scrollTo:"],a[href^="file:"],a[href^="#"]')) {
            link.removeEventListener('click', handleAnchorClick);
            link.addEventListener('click', handleAnchorClick);
        }


        let highlight_btn = root_node.querySelector("#highlight-functionName-btn")
        if (highlight_btn) {
            highlight_btn.addEventListener('click', (evt) => {
                let highlight_text = evt.target.getAttribute('value')
                if (highlight_text) {
                    setHighlight(highlight_text)
                }
            })
        }

        let search_scope_btns = root_node.querySelectorAll("[search_regex]")
        for (const search_scope_btn of search_scope_btns) {
            search_scope_btn.onclick = (evt) => {
                // let func_search_regex = evt.target.getAttribute('search_regex')

                // document.querySelector("#function-selector-textbox").value = func_search_regex
                // searchFunctions()

                handleSearchScopeClick(evt)
            }
        }

        const function_reviewed_checkbox = root_node.querySelector('#function-reviewed-checkbox')
        if (function_reviewed_checkbox && !function_reviewed_checkbox.dataset?.clickBound) {
            function_reviewed_checkbox.addEventListener('click', (evt) => {
                let s = vscode.getState()
                vscode.postMessage({
                    command: "mark_function_reviewed",
                    funcId: s.function_history_ids[s.function_history_index],
                    value: evt.target.checked
                })

                // update current stack of history
                let curr_func_id = s.function_history_ids[s.function_history_index]

                if (s.function_history) {
                    s.function_history.filter(f => {
                        return f.id === curr_func_id
                    }).forEach(f => {
                        f.reviewed = evt.target.checked
                    })
                    vscode.setState(s)
                }
            })  
            function_reviewed_checkbox.dataset.clickBound = true
        }

        const function_hide_incoming_outgoing_callstacks_checkboxes = root_node.querySelectorAll('#function-hide-incoming-callstacks-checkbox,#function-hide-outgoing-callstacks-checkbox')
        if (function_hide_incoming_outgoing_callstacks_checkboxes) {
            function_hide_incoming_outgoing_callstacks_checkboxes.forEach(checkbox => {
                if (checkbox.dataset?.clickBound) {
                    return
                }

                checkbox.addEventListener('click', (evt) => {
                    let s = vscode.getState()
                    // TODO: what is this? Do i need to update this "direction"
                    vscode.postMessage({
                        command: "set_hide_callstacks_from_function",
                        f_id: s.function_history_ids[s.function_history_index],
                        value: evt.target.checked,
                        direction: evt.target.getAttribute('data-mode')
                    })
    
                    // update current stack of history
                    let curr_func_id = s.function_history_ids[s.function_history_index]
    
                    if (s.function_history) {
                        s.function_history.filter(f => {
                            return f.id === curr_func_id
                        }).forEach(f => {
                            f.hide_incoming_callstacks = evt.target.checked
                        })
                        vscode.setState(s)
                    }
                })

                checkbox.dataset.clickBound = true
            })
        }


        const function_update_decorator = root_node.querySelector('#function-update-decorator')
        if (function_update_decorator && !function_update_decorator.dataset?.clickBound) {
            function_update_decorator.addEventListener('keyup', (evt) => {
                let s = vscode.getState()
                vscode.postMessage({
                    command: "update_decorator",
                    funcId: s.function_history_ids[s.function_history_index],
                    value: evt.target.value
                })

                // update current stack of history
                s.function_history.filter(f => {
                    return f.id === s.function_history_ids[s.function_history_index]
                }).forEach(f => {
                    f.decorator = evt.target.value
                })
                vscode.setState(s)
            })
            function_update_decorator.dataset.clickBound = true
        }

        

        const function_update_notes = root_node.querySelector('#function-notes')
        if (function_update_notes && !function_update_notes.dataset?.clickBound) {
            function_update_notes.addEventListener('keyup', (evt) => {
                clearTimeout(typingTimer);
                typingTimer = setTimeout(function () {
                    let s = vscode.getState()
                    vscode.postMessage({
                        command: "update_function_notes",
                        funcId: s.function_history_ids[s.function_history_index],
                        value: evt.target.value
                    })

                    // update current stack of history
                    if (s.function_histroy) {
                        s.function_history.filter(f => {
                            return f.id === s.function_history_ids[s.function_history_index]
                        }).forEach(f => {
                            f.decorator = evt.target.value
                        })

                        vscode.setState(s)
                    }
                }, 250);
            })
            function_update_notes.dataset.clickBound = true
        }

        // include related callstacks button
        let include_related_callstacks_btn = document.querySelector('#include-related-callstacks-btn')
        if (include_related_callstacks_btn) {
            include_related_callstacks_btn.onclick = function (evt) {
                // let scope_id = evt.target.getAttribute('value')

                window.include_related_callstacks = !window.include_related_callstacks
                include_related_callstacks_btn.setAttribute('value', window.include_related_callstacks)
                include_related_callstacks_btn.innerText = window.include_related_callstacks ? "Including Related Callstacks" : "Excluding Related Callstacks"
            }
        }

        let ctnt_uses_gitignore_btn = document.querySelector('#ctnt-uses-gitignore-btn')
        if (ctnt_uses_gitignore_btn) {
            ctnt_uses_gitignore_btn.onclick = function (evt) {
                let value = evt.target.getAttribute('value')
                let newValue = value === "true" ? "false" : "true"

                vscode.postMessage({command: "toggle_ctnt_uses_gitignore", value: newValue})

                ctnt_uses_gitignore_btn.setAttribute('value', newValue)
                ctnt_uses_gitignore_btn.innerText = newValue === "true" ? "Ctnt uses .gitignore" : "Ctnt doesn't use .gitignore"
            }
        }

        let force_data_update_btn = document.querySelector('#force-data-update-btn')
        if (force_data_update_btn) {
            force_data_update_btn.onclick = function (evt) {
                vscode.postMessage({command: "force_data_update"})
            }
        }

        let callstacks_graph_mode_btn = document.querySelector('#callstacks-graph-mode-btn')
        if (callstacks_graph_mode_btn) {
            callstacks_graph_mode_btn.onclick = function (evt) {
                let mode = evt.target.getAttribute('value')
                let newMode = mode === "Combined" ? "Split" : "Combined"

                window.callstacks_graph_mode = newMode
                callstacks_graph_mode_btn.setAttribute('value', window.callstacks_graph_mode)
                callstacks_graph_mode_btn.innerText = `Fn Graph Mode: ${window.callstacks_graph_mode}`
            }
        }

        // toggle-interesting-functions-mode-btn
        let show_all_functions_btn = document.querySelector('#show-all-functions-btn')
        if (show_all_functions_btn) {
            show_all_functions_btn.onclick = function (evt) {
                let mode = evt.target.getAttribute('value')
                let newMode = mode === "true" ? "false" : "true"

                vscode.postMessage({command: "togogle_interesting_functions_mode", value: newMode})

                show_all_functions_btn.setAttribute('value', newMode)
                show_all_functions_btn.innerText = newMode === "true" ? "Showing All Functions" : "Showing Interesting Functions"
            }
        }

        // help button
        let help_btn = document.querySelector("#toggle-help")
        if (help_btn) {
            help_btn.onclick = () => {
                vscode.postMessage({command: "toggleHelpHTML"})
            }
        }

        const settingsBtn = document.querySelector('#settings-btn')
        if (settingsBtn && !settingsBtn.dataset.clickBound) {
            settingsBtn.addEventListener('click', (evt) => {
                let settings = document.querySelector('#settings')
                if (settings.style.display === "none" || settings.style.display === "") {
                    settings.style.display = "block"
                } else {
                    settings.style.display = "none"
                }
                // get new height of sticky header with additional lines from newly shown elements

                evt.stopPropagation()
                evt.preventDefault()
            })
            settingsBtn.dataset.clickBound = true
        }

        const copilotChatBtn = document.querySelector('#send-to-copilot-chat-btn')
        if (copilotChatBtn && !copilotChatBtn.dataset.clickBound) {
            copilotChatBtn.addEventListener('click', async (evt) => {
                if (copilotChatWindowOpen) {
                    document.querySelector('#copilot-chat-cancel-btn').click()
                    return
                }
                openCopilotChatPrompt()
                evt.stopPropagation()
                evt.preventDefault()
            })
            copilotChatBtn.dataset.clickBound = true
        }

        // Scope Functionality
        let scope_input_exclude = document.querySelector("#scope-regex-exclude-filter")
        if (scope_input_exclude) {
            scope_input_exclude.onkeyup = (evt) => {
                window.scope_filter_exclude_regex = evt.target.value
                updateScopeHTML(window.scope_filter_regex, window.scope_filter_exclude_regex, window.scope_is_collapsed, window.scope_is_collapsed_2)
            }
        }

        let scope_regex_filter = document.querySelector("#scope-regex-filter")
        if (scope_regex_filter) {
            scope_regex_filter.onkeyup = (evt) => {
                window.scope_filter_regex = evt.target.value
                updateScopeHTML(window.scope_filter_regex, window.scope_filter_exclude_regex, window.scope_is_collapsed, window.scope_is_collapsed_2)
            }
        }

        let show_scope_graph_btn = document.querySelector('#show-scope-graph-btn')
        if (show_scope_graph_btn) {
            show_scope_graph_btn.onclick = function (evt) {
                let scope_id = evt.target.getAttribute('value')
                toggleScopeGraph(scope_id, 'interactions', false, false, window.include_related_callstacks)
            }
        }

        let show_scope_graph_inherited_btn = document.querySelector('#show-scope-graph-inherited-btn')
        if (show_scope_graph_inherited_btn) {
            show_scope_graph_inherited_btn.onclick = function (evt) {
                let scope_id = evt.target.getAttribute('value')
                toggleScopeGraph(scope_id, 'interactions', false, true, window.include_related_callstacks)
            }
        }

        let open_scope_in_browser_btn = document.querySelector('#open-scope-in-browser-btn')
        if (open_scope_in_browser_btn) {
            open_scope_in_browser_btn.onclick = function (evt) {
                let content = document.querySelector('#scope-detail').innerHTML
                // regex to replace all strings starting with vscode://file/ and replace # with :
                content = content.replace(
                    /(['"])(file:\/\/[^'"]*)\1/g,
                    (match, quote, content) => {
                        // Replace all '#' with ':' in the URL part
                        const updatedContent = content.replace(/#/g, ':');
                        return quote + updatedContent + quote;
                    }
                );
                
                content = content.replaceAll('file://', 'vscode://file/')
                
                vscode.postMessage({ command: "show_content_in_browser", content: content });
            }
        }
        

        let show_inheritance_graph_btn = document.querySelector('#show-inheritance-graph-btn')
        if (show_inheritance_graph_btn) {
            show_inheritance_graph_btn.onclick = function (evt) {
                let scope_id = evt.target.getAttribute('value')
                toggleScopeGraph(scope_id, 'inheritance')

                waitForElement('.cy-scope-filterSearchTerm', function() {
                    document.querySelector('.cy-scope-filterSearchTerm').click()
                })
            }
        }

        let checkbox_toggle_btn = document.querySelector('#scope-checkbox-toggle-btn')
        if (checkbox_toggle_btn) {
            checkbox_toggle_btn.onclick = function (evt) {
                window.scope_showing_unchecked = !window.scope_showing_unchecked
                checkbox_toggle_btn.innerText = window.scope_showing_unchecked ? "Showing Unchecked" : "Hiding Unchecked"

                let scope_ele = document.querySelector('#scope-detail')
                let checkboxes = scope_ele.querySelectorAll('input[type="checkbox"]')
                let unchecked_containers = Array.from(checkboxes).filter(cb => { return !cb.checked && cb.parentElement.classList.contains('collapsable') }).map(cb => { return cb.parentElement })
                Array.from(unchecked_containers).forEach(cb => {
                    function getParentStateCheckboxValue(ele) {
                        if (!ele) return null
                        return ele?.previousElementSibling?.tagName === 'SPAN' ? ele.previousElementSibling.querySelector('input[type="checkbox"]').checked : getParentStateCheckboxValue(ele?.previousElementSibling)
                    }

                    let parent_cb = getParentStateCheckboxValue(cb)

                    cb.style.display = window.scope_showing_unchecked || parent_cb ? 'block' : 'none' 
                })
            }
        }

        let scope_collapse_btn = document.querySelector('#scope-collapse-btn')
        if (scope_collapse_btn) {
            scope_collapse_btn.onclick = function (evt) {
                window.scope_is_collapsed = !window.scope_is_collapsed
                evt.target.innerText = window.scope_is_collapsed ? "Hiding Collapsable" : "Showing Collapsable"

                let regex = document.querySelector('#scope-regex-filter').value
                updateScopeHTML(regex, window.scope_filter_exclude_regex, window.scope_is_collapsed, window.scope_is_collapsed_2)
            }
        }

        let scope_collapse_2_btn = document.querySelector('#scope-collapse-2-btn')
        if (scope_collapse_2_btn) {
            scope_collapse_2_btn.onclick = function (evt) {
                window.scope_is_collapsed_2 = !window.scope_is_collapsed_2
                evt.target.innerText = window.scope_is_collapsed_2 ? "Hiding Collapsable 2" : "Showing Collapsable 2"

                let regex = document.querySelector('#scope-regex-filter').value
                updateScopeHTML(regex, window.scope_filter_exclude_regex, window.scope_is_collapsed, window.scope_is_collapsed_2)
            }
        }

        // state var buttons        
        let setStateVarBtns = document.querySelectorAll(".setStateVar")
        if (setStateVarBtns) {
            Array.from(setStateVarBtns).forEach(btn => {
                btn.onclick = function (evt) {
                    setSelectedStateVar(evt.target)
                }
            })
        }

        let setManualRelationshipBtns = document.querySelectorAll(".manual-relationship-link")
        if (setManualRelationshipBtns) {
            Array.from(setManualRelationshipBtns).forEach(btn => {
                btn.onclick = function (evt) {
                    joinFunctions(evt.target.getAttribute('value'), evt.ctrlKey)
                }
            })
    }




        // add scroll listeners
        function handleScroll() {
            // make graph header sticky
            let showing_threshold = .25
            let top_buffer = 150 // 45
            let container_headers = document.querySelectorAll("[id^='cy-'][id$='-container']")
        
            for (let container_header of container_headers) {
                var header = container_header;
                var graph_body = document.getElementById(container_header.id.replace("-container", ""));
                
                let showing_percentage = graph_body.getBoundingClientRect().bottom / graph_body.getBoundingClientRect().height
                // console.log(graph_body.getBoundingClientRect().bottom, graph_body.getBoundingClientRect().height, showing_percentage)
                if (graph_body.getBoundingClientRect().top - top_buffer < 0 && graph_body.getBoundingClientRect().bottom > top_buffer && showing_percentage > showing_threshold) {
                    // sticky when graph is going off screen and at top 
                    header.style.position = 'sticky';
                } else {
                    header.style.position = 'static'; 
                }
            }

            // hide settings menu
            let settings = document.querySelector('#settings')
            settings.style.display = "none"
        }
        
        window.onscroll = () => { handleScroll() }
        let func_summary_ele = document.querySelector('#function-summary')
        if (func_summary_ele) func_summary_ele.onscroll = () => { handleScroll() }
        let scope_detail_ele = document.querySelector('#scope-detail')
        if (scope_detail_ele) scope_detail_ele.onscroll = () => { handleScroll() }
    }
    AddEventListeners(document);



 
    let all_inheritance_graph_btn = document.querySelector('#show-all-inheritance-graph-btn')
    let in_scope_graph_btn = document.querySelector('#show-all-scope-graph-btn')
    let showing_in_scope_graph = false
    function toggleScopeGraph(scope_id, type, scope_only = false, include_inherited_funcs = true, include_related_callstacks = false) {
        showing_in_scope_graph = !showing_in_scope_graph

        let show_hide = showing_in_scope_graph ? "Hide" : "Show"

        let inheritance_graph_btn = document.querySelector('#show-inheritance-graph-btn')
        if (inheritance_graph_btn) {
            inheritance_graph_btn.innerText = `${show_hide} Inheritance Graph`
        }
        
        let scope_graph_btn = document.querySelector('#show-scope-graph-btn')
        if (scope_graph_btn) {
            scope_graph_btn.innerText = `${show_hide} Scope Graph`
        }

        let search_callstacks_graph_btn = document.querySelector('#show-callstacks-graph-with-search-term-btn')
        if (search_callstacks_graph_btn) {
            search_callstacks_graph_btn.innerText = `${show_hide} Callstacks Graph w/ Search Term`
        }

        let scope_graph_inherited_btn = document.querySelector('#show-scope-graph-inherited-btn')
        if (scope_graph_inherited_btn) {
            scope_graph_inherited_btn.innerText = `${show_hide} Scope (inherited) Graph`
        }

        let graph_ele = document.querySelector('#scope-graph-container')
        if (showing_in_scope_graph) {
            graph_ele.style.display = 'block'
            all_inheritance_graph_btn.innerText = "Hide Inheritance Graph"
            in_scope_graph_btn.innerText = "Hide All Scopes Graph"

            switch (type) {
                case 'interactions':
                    vscode.postMessage({ command: "show_scope_graph", scope_id: scope_id, scope_only: scope_only, include_inherited_funcs: include_inherited_funcs, include_related_callstacks });
                    break;
                case 'inheritance':
                    vscode.postMessage({ command: "show_inheritance_graph", scope_id: scope_id });
                    if (!scope_id.startsWith('all'))
                        setHighlight(scope_id.split(",")[0])
                    break;
            }
            
            graph_ele.scrollIntoView({behavior: 'smooth', block: 'start'});
        } else {
            all_inheritance_graph_btn.innerText = "Show Inheritance Graph"
            in_scope_graph_btn.innerText = "Show All Scopes Graph"
            graph_ele.style.display = 'none'
            graph_ele.innerHTML = ''
        }
    }

    all_inheritance_graph_btn.addEventListener('click', (evt) => {
        toggleScopeGraph('all', 'inheritance')
    })

    in_scope_graph_btn.addEventListener('click', (evt) => {
        toggleScopeGraph('all~', 'interactions', true)
    })



    let show_callstacks_search_term_btn = document.querySelector('#show-callstacks-graph-with-search-term-btn')
    if (show_callstacks_search_term_btn) {
        show_callstacks_search_term_btn.onclick = function (evt) {
            let search_term = document.querySelector('#search-textbox').value
            if (search_term) {
                // let scope_id = evt.target.getAttribute('value')
                toggleScopeGraph(`all~${search_term}`, 'interactions', false, true, window.include_related_callstacks)
            }
        }
    }


    document.querySelector('#toggle-reviewed').addEventListener('change', (ele) => {
        vscode.postMessage({command: "toggle_hide_reviewed", hideReviewedState: document.querySelector('#toggle-reviewed').selectedOptions[0].innerText });
    });

    window.searchFunc = searchFunctions // default to searching functions
    document.querySelector('#search-functions').addEventListener('click', () => {
        window.searchFunc = searchFunctions
        window.searchFuncMode = "identifier"
        searchFunctions();
    });

    window.searchFunc = searchFunctions // default to searching functions
    window.searchFuncShift = false
    document.querySelector('#search-functions-content').addEventListener('click', (evt) => {
        window.searchFuncShift = evt.shiftKey;
        window.searchFunc = searchFunctions
        window.searchFuncMode = "content"
        searchFunctions();
    });

    document.querySelector('#search-scopes').addEventListener('click', () => {
        window.searchFunc = searchScopes
        searchScopes()
    });

    document.querySelector('#function-selector-textbox').addEventListener('keyup', (evt) => {
        if (evt.ctrlKey || evt.key === "Control" || window.searchFuncMode === "content") return
        clearTimeout(typingTimer);
        typingTimer = setTimeout(window.searchFunc, doneTypingInterval);
    });

    document.querySelector('#function-selector-exclude-textbox').addEventListener('keyup', (evt) => {
        if (evt.ctrlKey || evt.key === "Control" || window.searchFuncMode === "content") return
        clearTimeout(typingTimer);
        typingTimer = setTimeout(window.searchFunc, doneTypingInterval);
    });

    document.querySelector('#search-textbox').addEventListener('keyup', (evt) => {
        const isEnterKey = evt.key === 'Enter';
        if (window.searchFuncMode === "content" && isEnterKey) {
            window.searchFuncShift = evt.shiftKey;
            clearTimeout(typingTimer);
            window.searchFunc()
        }
    });

    document.querySelector('#btn-mark-all-reviewed').addEventListener('click', () => {
        vscode.postMessage({command: "mark_all_reviewed" });
    })

    document.querySelector('#btn-bulk-update-decorator').addEventListener('click', () => {

        vscode.postMessage({command: "bulk_update_decorator" });
    })

    document.querySelector('#select-function-sort').addEventListener('change', (evt) => {
        vscode.postMessage({command: "set_function_sort_option", sortOption: document.querySelector('#select-function-sort').selectedOptions[0].innerText });
    })

    document.querySelector('#btn-load').addEventListener('click', (evt) => {
        evt.target.disabled = true
        vscode.postMessage({command: "load", lastFunction: window.lastFunction, lastScope: window.lastScope});
    })

    document.querySelector('#btn-save').addEventListener('click', (evt) => {
        evt.target.disabled = true
        vscode.postMessage({command: "save"});
    })


    document.querySelector('#search-textbox').addEventListener('keyup', () => {
        clearTimeout(typingTimer);
        typingTimer = setTimeout(() => { 
            reloadGraphs(); 
            setTimeout(highlightSearchRegex, doneTypingInterval) // race condition with sync graph updates, consider tying to event
        }, doneTypingInterval);
    });

    function setHighlight(highlight_text) {
        if (highlight_text) {
            document.querySelector("#search-textbox").value = highlight_text
            document.querySelector("#search-textbox").dispatchEvent(new KeyboardEvent('keyup'))
            // highlightSearchRegex()
        }
    }

    function highlightSearchRegex(maxDepth = 5) { // triggers when textbox is updated
        let inputText = document.getElementById('search-textbox').value;
        
        // input too short
        // if (inputText.length < 3) 
        //     return

        // reloadGraphs()
    
        let context = document.getElementById('content');
        var instance = new Mark(context);
        instance.unmark();

        // document.querySelectorAll('code').forEach(ele => { ele.removeAttribute('data-highlighted') })

        // language highlights
        const language_selection = document.querySelector('#select-syntax-highlighter').selectedOptions[0].innerText

        if (language_selection !== 'Disabled') {
            hljs.highlightAll(); // run HighlighJS to automatically tag code blocks (language detection)
            if (language_selection === 'Prism') {
            Prism.highlightAll();
            }
        }

        const re = new RegExp(escapeRegExp(inputText), 'i');
        instance.markRegExp(re, {
            "separateWordSearch": false,
            "acrossElements": true
        });
        // AddEventListeners(content)
    }

    function searchScopes() {
        let regexPattern = document.querySelector('#function-selector-textbox').value
        let excludeRegexPattern = document.querySelector('#function-selector-exclude-textbox').value

        vscode.postMessage({command: "search_scopes", regex: regexPattern, exclude_regex: excludeRegexPattern})
    }

    function escapeStringForRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    function searchFunctions() {
        if (window.searchFuncMode === "content") {
            // searching codebase could take a while, disable other search buttons to indicate we are still searching via. ripgrep
            document.querySelector("#search-functions-content").disabled = true
            document.querySelector("#search-functions").disabled = true
            document.querySelector("#search-scopes").disabled = true
        }
        let regexPattern = document.querySelector('#function-selector-textbox').value
        let excludeRegexPattern = document.querySelector('#function-selector-exclude-textbox').value
        let cntRegexPattern = document.querySelector('#search-textbox').value


        if (window.searchFuncShift) {
            cntRegexPattern = escapeStringForRegex(cntRegexPattern)
        }

        vscode.postMessage({command: "search_functions", regex: regexPattern, exclude_regex: excludeRegexPattern, cnt_regex: cntRegexPattern, mode: window.searchFuncMode || "identifier"})
    }

    document.querySelector('#function-back').style.cursor = 'pointer'
    document.querySelector('#function-back').addEventListener('click', () => {
        let s = vscode.getState()
        if (s.function_history_index - 1 < 0) 
            return
        
        s.function_history_index --
        vscode.setState(s)
        vscode.postMessage({
            command: "show_function",
            function_id: s.function_history_ids[s.function_history_index],
            navigated_from_history: true,
            mode: window.callstacks_graph_mode, 
            include_related_callstacks: window.include_related_callstacks
        })
        // setSelectedFunction(s.function_history[s.function_history_index])
    });

    document.querySelector('#function-forward').style.cursor = 'pointer'
    document.querySelector('#function-forward').addEventListener('click', () => {
        let s = vscode.getState()
        if (s.function_history_index + 1 >= s.function_history_ids.length) 
            return
        
        s.function_history_index ++
        vscode.setState(s)
        // vscode.postMessage({command: "show_function", function_id: s.function_history[s.function_history_index], navigated_from_history: true})
        vscode.postMessage({
            command: "show_function",
            function_id: s.function_history_ids[s.function_history_index],
            navigated_from_history: true,
            mode: window.callstacks_graph_mode, 
            include_related_callstacks: window.include_related_callstacks
        })
        // setSelectedFunction(s.function_history_ids[s.function_history_index])
    });

    function updateScopeHTML(regex_filter = null, regex_exclude_filter = null, is_collapsed = false, is_collapsed_2 = false) {
        let regex = new RegExp(escapeRegExp(regex_filter), 'i');
        let regex_exclude = new RegExp(escapeRegExp(regex_exclude_filter), 'i');
        let eles = document.querySelector('#scope-detail').querySelector('.content').querySelectorAll('div, span')
        for (ele of eles) { // handle collapsed
            if (is_collapsed && ele.classList.contains("collapsable")) {
                ele.style.display = 'none'
                continue
            }

            if (is_collapsed_2 && ele.classList.contains("collapsable-2")) {
                ele.style.display = 'none'
                continue
            }

            // hide excluded items
            if (regex_exclude_filter && regex_exclude.test(ele.innerText)) {
                ele.style.display = 'none'
                continue
            }

            // handle regex filter
            if (! regex_filter || regex.test(ele.innerText)) {
                ele.style.display = ''
            } else {
                ele.style.display = 'none'
            }
        }


    }


    function setScope(scope_id, graph) {
        scope_id = scope_id || window.lastScope.id
        graph = graph || main_module?.last_graph_interacted?.json()?.elements
        
        let checkbox_ids_to_check = []
        if (graph) {
            // `graph` comes from loading a graph, 
            let nodes = graph.nodes || graph
            checkbox_ids_to_check = Array.from(nodes)
                // .filter(n => { return n.group === 'nodes' })
                .map(n => {   
                    let is_selected_func = window.lastFunction && n.data.id === window.lastFunction.id ? 'yellow' : ''
                    let color = is_selected_func || n.data?.backgroundColor || (window.lastFunction && n.data.id !== window.lastFunction.id ? 'orange' : '')
                    return `${n.data.id}~~${color}` 
                })
            
        }
        vscode.postMessage({command: "show_scope", scope_id: scope_id, checkbox_ids_to_check: checkbox_ids_to_check})
        
    }

    window.scope_showing_unchecked = true
    window.scope_is_collapsed = false
    window.scope_is_collapsed_2 = false
    window.scope_filter_regex = ''
    window.scope_filter_exclude_regex = ''
    window.lastScope = null
    function setSelectedScope(scope, checkbox_ids_to_check) {
        let scope_ele = document.querySelector('#scope-detail')

        function setCheckboxColors() {
            checkbox_ids_to_check.forEach(id_w_color => {
                let id = id_w_color.split("~~")[0]
                let color = id_w_color.split("~~")[1] || ''  // default color to empty string
                let eles = scope_ele.querySelectorAll(`[id*="~${id}"],[id="function-${id}"],[id="${id}"]`)
                for (let ele of eles) {
                    ele.checked = true
                    ele.style.accentColor = color
                    
    
                    // highlight parent, yellow means it's currently the selected function
                    let state_var_name = ele.getAttribute('id').split("~")[0]
                    let parent = document.querySelector(`[id^="statevar-${state_var_name}"]`)
                    if (parent) {
                        parent.checked = true
                        if (!(parent.style.accentColor === 'yellow')) {
                            parent.style.accentColor = color
                        }
                    }

                    let var_table_of_contents = document.querySelector(`[id^="statevar-toc-${state_var_name}"]`)
                    if (var_table_of_contents) {
                        var_table_of_contents.checked = true
                        
                        if (!(var_table_of_contents.style.accentColor === 'yellow')) {
                            var_table_of_contents.style.accentColor = color
                        }
                    }
                }
            })
        }

        if (window.lastScope?.scope === scope) {
            scope_ele.querySelectorAll('input[type="checkbox"]').forEach(checkbox => { checkbox.checked = false})

            setCheckboxColors()
            return
        }

        window.lastScope = { scope: scope, checkbox_ids_to_check: checkbox_ids_to_check }

        scope_ele.innerHTML = ''


        let sticky_header = document.createElement('div')
        sticky_header.className = "sticky-header sticky-header-secondary"

        let title = document.createElement('h2')
        title.id = "scope-detail-title"
        title.style.margin = '0'
        title.innerText = `Scope Summary: ${scope.name}`
        sticky_header.appendChild(title)

        let open_in_browser_btn = document.createElement('button')
        open_in_browser_btn.id = "open-scope-in-browser-btn"
        open_in_browser_btn.innerText = "Open in Browser"
        sticky_header.appendChild(open_in_browser_btn)

        let show_inheritance_graph_btn = document.createElement('button')
        show_inheritance_graph_btn.id = "show-inheritance-graph-btn"
        show_inheritance_graph_btn.innerText = showing_in_scope_graph ? "Hide Inheritance Graph" : "Show Inheritance Graph"
        show_inheritance_graph_btn.setAttribute('value', scope.id)
        // onclick added from AddEventListeners
        sticky_header.appendChild(show_inheritance_graph_btn)

        let show_scope_graph_btn = document.createElement('button')
        show_scope_graph_btn.id = "show-scope-graph-btn"
        show_scope_graph_btn.innerText = showing_in_scope_graph ? "Hide Scope Graph" : "Show Scope Graph"
        show_scope_graph_btn.setAttribute('value', scope.id)
        // onclick added from AddEventListeners
        sticky_header.appendChild(show_scope_graph_btn)

        let show_scope_graph_inherited_btn = document.createElement('button')
        show_scope_graph_inherited_btn.id = "show-scope-graph-inherited-btn"
        show_scope_graph_inherited_btn.innerText = showing_in_scope_graph ? "Hide Scope (inherited) Graph" : "Show Scope (inherited) Graph"
        show_scope_graph_inherited_btn.setAttribute('value', scope.id)
        // onclick added from AddEventListeners
        sticky_header.appendChild(show_scope_graph_inherited_btn)

        let br = document.createElement('br')
        sticky_header.appendChild(br)

        let checkbox_toggle_btn = document.createElement('button')
        checkbox_toggle_btn.id = "scope-checkbox-toggle-btn"
        checkbox_toggle_btn.innerText = window.scope_showing_unchecked ? "Showing Unchecked" : "Hiding Unchecked"
        // onclick added from AddEventListeners
        sticky_header.appendChild(checkbox_toggle_btn)

        let btn = document.createElement('button')
        btn.id = "scope-collapse-btn"
        btn.innerText = window.scope_is_collapsed ? "Hiding Collapsable" : "Showing Collapsable"
        // onclick added from AddEventListeners
        sticky_header.appendChild(btn)

        let btn2 = document.createElement('button')
        btn2.id = "scope-collapse-2-btn"
        btn2.innerText = window.scope_is_collapsed_2 ? "Hiding Collapsable 2" : "Showing Collapsable 2"
        // onclick added from AddEventListeners
        sticky_header.appendChild(btn2)

        if (document.querySelector('#select-search-template')) {
            let scope_search_templates = document.createElement('select')
            scope_search_templates.id = "select-search-template-scope"
            scope_search_templates.innerHTML = document.querySelector('#select-search-template').innerHTML
            // onkeyup set in AddEventListeners()
            sticky_header.appendChild(scope_search_templates)
        }

        let input = document.createElement('input')
        input.id = "scope-regex-filter"
        input.placeholder = "regex filter"
        input.value = window.scope_filter_regex
        // onkeyup set in AddEventListeners()
        sticky_header.appendChild(input)

        let input_exclude = document.createElement('input')
        input_exclude.id = "scope-regex-exclude-filter"
        input_exclude.placeholder = "exclude regex filter"
        input_exclude.value = window.scope_filter_exclude_regex
        // onkeyup set in AddEventListeners()
        sticky_header.appendChild(input_exclude)



        scope_ele.appendChild(sticky_header)

        let html = `
        <div class='content'>
            (#inherits ${scope.inherits_recursive.length} in<>out ${scope.inherits_from_recursive.length})<br>
            ${
                decompressHexString(scope.scope_summary_html)
            }
        </div>
        `

        scope_ele.insertAdjacentHTML('beforeend', html)

        setCheckboxColors()

        AddEventListeners(document.querySelector('#content'))
        adjustContainerHeight()
        updateScopeHTML(window.scope_filter_regex, window.scope_filter_exclude_regex, window.scope_is_collapsed, window.scope_is_collapsed_2)
    }

    window.lastFunction = null
    function setSelectedFunction(func) { // hide functions list + dissable review buttons
        document.querySelector('#functions-list').style.display = 'none'
        document.querySelector('#btn-mark-all-reviewed').disabled = true
        document.querySelector('#btn-bulk-update-decorator').disabled = true


        let scope_regex = GetScopeRegexOfFunc(func.qualifiedName)
        let search_scope_btn = document.createElement('span')
        search_scope_btn.id = "search-scope"
        search_scope_btn.style.cursor = 'pointer'
        search_scope_btn.style.paddingRight = '2px'
        search_scope_btn.innerText = `🔍`
        search_scope_btn.setAttribute('search_regex', scope_regex)

        let set_function_btn = document.createElement('a')
        set_function_btn.style.textDecoration = 'none'
        set_function_btn.style.cursor = 'pointer'
        set_function_btn.style.paddingRight = '5px'
        set_function_btn.setAttribute('href', `#${
            func.id
        }`)
        set_function_btn.setAttribute('data-scope', func.scope_id)
        set_function_btn.innerText = "🔗"
        // set_function_btn.onclick = (evt) => {
        //     vscode.postMessage({command: "show_function", function_id: evt.target.getAttribute('href').slice(1), mode: window.callstacks_graph_mode, include_related_callstacks: window.include_related_callstacks})
        // } 
        // is this needed? may be set by AddEventListeners


        let highlight_func_btn = document.createElement('span')
        highlight_func_btn.id = "highlight-functionName-btn"
        highlight_func_btn.style.cursor = 'pointer'
        highlight_func_btn.style.paddingRight = '2px'
        highlight_func_btn.innerText = `🖊`
        // highlight_func_btn.value = func.functionName
        highlight_func_btn.setAttribute('value', `${
            func.functionName
        }`)


        let html = `
        <div id='${
            func.id
        }' class='function-summary'><h1>Function Summary</h1>
        <h2 class="sticky-header sticky-header-secondary">${ search_scope_btn.outerHTML + set_function_btn.outerHTML + highlight_func_btn.outerHTML } (Taints: ${func.tainted_locations_count || "?"}) (SLOC: ${func.endLine - func.startLine || '?'}) <a href='file://${
            func.filepath
        }'>${
            func.qualifiedName || func.functionName
        }</a> | <input type="text" id="function-update-decorator" value='${
            func.decorator.replace(/'/g, "&#39;")
        }' /></h2>

        ${ func.function_summary_html ? func.function_summary_html : "" }

        
        <input type="checkbox" id="function-reviewed-checkbox" ${
            func.reviewed ? 'checked' : ''
        }>
        <label for="function-reviewed-checkbox">mark function as reviewed</label>&emsp;

        <input type="checkbox" id="function-hide-incoming-callstacks-checkbox" data-mode="incoming" ${
            func.hide_incoming_callstacks ? 'checked' : ''
        }>
        <label for="function-hide-incoming-callstacks-checkbox">hide incoming callstacks</label>&emsp;
        
        <input type="checkbox" id="function-hide-outgoing-callstacks-checkbox" data-mode="outgoing" ${
            func.hide_outgoing_callstacks ? 'checked' : ''
        }>
        <label for="function-hide-outgoing-callstacks-checkbox">hide outgoing callstacks</label><br>
        
        <textarea id="function-notes" placeholder="function notes" style="height: 5em; width: 50em">${
            func.function_notes || ""
        }</textarea><br>
        
        ${
            func.related_functions_html ? '<h3>Related Functions (by name)</h3>' + func.related_functions_html : ''
        }

        ${
            func.additional_info_html ? func.additional_info_html : ""
        }

        ${
            func.state_vars_summary_html ? func.state_vars_summary_html : ""
        }
        
        ${
            func.entrypoint_callstacks_html ? func.entrypoint_callstacks_html : ""
        }
        ${ window.callstacks_graph_mode === "Split" && func.entrypoint_callstacks_graph?.nodes?.length > 0 ? '<div id="cy-entrypoint-container"></div><div id="cy-entrypoint"></div>' : "" }

        ${
            func.exit_callstacks_html ? func.exit_callstacks_html : ""
        }
        ${ window.callstacks_graph_mode === "Split" && func.exit_callstacks_graph?.nodes?.length > 0 ? '<div id="cy-exit-container"></div><div id="cy-exit"></div>' : "" }

        ${
            func.other_callstacks_html ? func.other_callstacks_html : ""
        }        
        ${ window.callstacks_graph_mode === "Split" && func.other_callstacks_graph?.nodes?.length > 0 ? '<div id="cy-other-container"></div><div id="cy-other"></div>' : "" }
       

        ${
            window.callstacks_graph_mode === "Combined" && func.callstacks_graph?.nodes?.length > 0 ? '<h3>Callstacks Graph</h3><div id="cy-callstacks-container"></div><div id="cy-callstacks"></div>' : "" 
        }

        ${
            func.related_callstacks_html ? func.related_callstacks_html : ""
        }
        ${ func.related_callstacks_graph?.nodes?.length > 0 ? '<div id="cy-related-container"></div><div id="cy-related"></div>' : "" }



        <h3>Tainted Param Usage</h3>
        ${
            func.tainted_locations_html
        }
        `

        let function_summary_wrapper = document.querySelector('#function-summary')
        function_summary_wrapper.innerHTML = html

        clearCytoscapeInstances("function")
        switch (window.callstacks_graph_mode) {
            case "Split":
                if (func.entrypoint_callstacks_graph?.nodes?.length > 0) {
                    createChart('cy-entrypoint', func.entrypoint_callstacks_graph)
                }
                if (func.exit_callstacks_graph?.nodes?.length > 0) {
                    createChart('cy-exit', func.exit_callstacks_graph)
                }
                if (func.other_callstacks_graph?.nodes?.length > 0) {
                    createChart('cy-other', func.other_callstacks_graph)
                }
                break
            case "Combined":
                if (func.callstacks_graph?.nodes?.length > 0 ) {
                    createChart('cy-callstacks', func.callstacks_graph)
                }
        }
        
        if (func.related_callstacks_graph?.nodes?.length > 0) {
            createChart('cy-related', func.related_callstacks_graph)
        }

        // add event handlers to newly rendered HTML
        AddEventListeners(document.querySelector('#content'))
        adjustContainerHeight()


        setHighlight(func.functionName)
        function_summary_wrapper.scrollIntoView({behavior: 'smooth', block: 'center'});

        window.lastFunction = func
    }

    function joinFunctions(f_id, ctrl_pressed = false) {
        vscode.postMessage({command: "manually_map_function_relationship", f_id: f_id, ctrl_pressed: ctrl_pressed })
    }

    // Handle messages sent from the extension to the webview
    window.addEventListener('message', event => {
        const message = event.data; // The json data that the extension sent	↑ 
        let functions_list_container = document.querySelector('#functions-list')

        switch (message.command) {
            case 'setElesDisabled':
                let eles = document.querySelectorAll(message.selector)
                for (ele of eles) {
                    ele.disabled = message.is_disabled
                }
                break;
            case 'searchScopes':
                functions_list_container.style.display = 'block'
                let scopes = message.scopeIdObjs

                var fragment = document.createDocumentFragment();

                let scope_close_btn = document.createElement('button')
                scope_close_btn.innerText = "Close"
                scope_close_btn.onclick = () => {
                    functions_list_container.style.display = 'none'
                }
                fragment.appendChild(scope_close_btn)

                let scope_h2 = document.createElement("h2")
                scope_h2.innerText = "Filtered Scopes"
                fragment.appendChild(scope_h2)

                for (let s of scopes) {
                    let scope = s.scopeDefinition
                    let li = document.createElement('li')

                    let scope_search_ele = document.createElement('span')
                    scope_search_ele.id = "search-scope"
                    scope_search_ele.style.cursor = 'pointer'
                    scope_search_ele.style.paddingRight = '2px'
                    scope_search_ele.innerText = `🔍`
                    scope_search_ele.setAttribute('search_regex', `^${scope.name}\\.`)
                    scope_search_ele.onclick = () => {
                        window.searchFunc = searchFunctions
                    }
                    li.appendChild(scope_search_ele)

                    let scope_set_ele = document.createElement('span')
                    scope_set_ele.id = "set-scope"
                    scope_set_ele.style.cursor = 'pointer'
                    scope_set_ele.style.paddingRight = '2px'
                    scope_set_ele.innerText = `🔷`
                    scope_set_ele.setAttribute('value', `${scope.id}`)
                    scope_set_ele.onclick = (evt) => {
                        let scope_id = evt.target.getAttribute('value')
                        let graph = main_module?.last_graph_interacted?.json()?.elements

                        setScope(scope_id, graph)
                        functions_list_container.style.display = 'none'
                    }
                    li.appendChild(scope_set_ele)

                    let linked_name = document.createElement('a')
                    linked_name.style.textDecoration = 'none'
                    linked_name.innerText = scope.name
                    linked_name.setAttribute('href', `file://${
                        scope.filepath
                    }`)
                    linked_name.style.cursor = 'pointer'
                    linked_name.onclick = (evt) => {
                        vscode.postMessage({command: "open", is_ctrl_click: evt.ctrlKey, link: evt.target.getAttribute('href')})
                    } 
                    li.appendChild(linked_name)

                    let span = document.createElement('span')
                    span.innerText = ` | ${scope.type ? `(${scope.type}) ` : ""}(#inherits ${scope.scope_summary.inherits_from_recursive.length} in<>out ${scope.scope_summary.inherits_from_recursive.length}) (#funcs: ${scope.numFunctions}) (#funcs_inherited: ${scope.numFunctions_inherited}) ${scope.decorator}... ${scope.filepath}`
                    li.appendChild(span)

                    // li.innerText = scope.name
                    fragment.appendChild(li)
                }


                functions_list_container.innerHTML = ""
                functions_list_container.appendChild(fragment)
                AddEventListeners(document.querySelector('#content'))

                highlightSearchRegex()

                scrollToTop()
                break;
            case 'searchFunctions': 

                console.log("starting processing of functions")
                let start = new Date().getTime()
                // set search buttons as searchable again
                document.querySelector("#search-functions-content").disabled = false
                document.querySelector("#search-functions").disabled = false
                document.querySelector("#search-scopes").disabled = false

                functions_list_container.style.display = 'block'
                let functions = message.functionIdObjs

                var fragment = document.createDocumentFragment();

                let func_close_btn = document.createElement('button')
                func_close_btn.innerText = "Close"
                func_close_btn.onclick = () => {
                    functions_list_container.style.display = 'none'
                }
                fragment.appendChild(func_close_btn)

                if (window.searchFuncMode === "content") {
                    let toggle_related_funcs_btn = document.createElement('button')
                    toggle_related_funcs_btn.innerText = "Toggle Related Functions"
                    toggle_related_funcs_btn.style.marginLeft = "5px"
                    toggle_related_funcs_btn.onclick = () => {
                        // toggle hiding <li> where class list contains 'has-locations'
                        let has_locations = document.querySelectorAll('.function-result:not(.has-locations)')
                        for (let ele of has_locations) {
                            if (ele.style.display === 'none') {
                                ele.style.display = ''
                            } else {
                                ele.style.display = 'none'
                            }
                        }

                    }
                    fragment.appendChild(toggle_related_funcs_btn)

                    let todetectors_btn = document.createElement('button')
                    todetectors_btn.innerText = "To Detectors"
                    todetectors_btn.style.marginLeft = "2em"
                    todetectors_btn.onclick = () => {
                        // Implement the logic to send the search term to the detectors
                        vscode.postMessage({command: "add_detectors", functions: functions})
                    }
                    fragment.appendChild(todetectors_btn)
                }

                let func_h2 = document.createElement("h2")
                func_h2.innerText = "Filtered Functions"
                fragment.appendChild(func_h2)

                let functions_list = document.createElement('ol')
                let current_scope = null
                let last_scope_seen = null

                for (let func of functions) {
                    if (last_scope_seen !== func.scope_id) {
                        if (last_scope_seen) {
                            let break_spacer = document.createElement('br')
                            functions_list.appendChild(break_spacer)
                        }

                        // add scope name
                        let scope_name_ele = document.createElement('div')
                        scope_name_ele.innerText = `-- ${func.scope_id} --`
                        functions_list.appendChild(scope_name_ele)
                    }
                    last_scope_seen = func.scope_id


                    let li = document.createElement('li')
                    li.classList.add('function-result')

                    let createRelationship = document.createElement('span')
                    createRelationship.textContent = "🪢"
                    createRelationship.style.cursor = 'pointer'
                    createRelationship.style.paddingRight = '5px'
                    createRelationship.onclick = (evt) => {
                        joinFunctions(func.id, evt.ctrlKey)
                    }
                    li.appendChild(createRelationship)

                    let scope_regex = GetScopeRegexOfFunc(func.name)
                    if (scope_regex !== current_scope) { // append new search scope ele
                        current_scope = scope_regex
                    }
                    let scope_ele = document.createElement('span')
                    scope_ele.id = "search-scope"
                    scope_ele.style.cursor = 'pointer'
                    scope_ele.style.paddingRight = '2px'
                    scope_ele.innerText = `🔍`
                    scope_ele.setAttribute('search_regex', scope_regex)
                    li.appendChild(scope_ele)


                    let span = document.createElement('a')
                    span.style.textDecoration = 'none'
                    span.style.cursor = 'pointer'
                    span.style.paddingRight = '5px'
                    span.setAttribute('href', `#${
                        func.id
                    }`)
                    span.setAttribute('data-scope', func.scope_id)
                    span.innerText = "🔗"
                    // event will be added via. AddEventListeners
                    // span.onclick = (evt) => {
                    //     vscode.postMessage({command: "show_function", function_id: evt.target.getAttribute('href').slice(1), mode: window.callstacks_graph_mode, include_related_callstacks: window.include_related_callstacks})
                    // } 
                    li.appendChild(span)


                    span = document.createElement('a')
                    span.style.textDecoration = 'none'
                    span.innerText = func.name
                    // span.setAttribute('href', `file://${func.name.split(",").slice(-1)[0].trim()}`)
                    span.setAttribute('href', `file://${
                        func.id.split(",").slice(-1)[0].trim()
                    }`)
                    span.style.cursor = 'pointer'
                    span.onclick = (evt) => {
                        vscode.postMessage({command: "open", is_ctrl_click: evt.ctrlKey, link: evt.target.getAttribute('href')})
                    } 
                    li.appendChild(span)

                    // handle locations
                    if (window.searchFuncMode === "content") {
                        const MAX_LOCS_DISPLAY = 200
                        const MAX_LOC_CHARS = 300
                        if (func.locs.length > 0) {
                            li.classList.add('has-locations');
    
                            let locs_list = document.createElement('ul')
                            for (let loc of func.locs.slice(0, MAX_LOCS_DISPLAY)) {
                                let isBlankFunc = func.id === "none"
                                if (isBlankFunc) {
                                    // Group by filepath
                                    let fileGroupId = `file-group-${btoa(loc.filepath).replace(/=/g, '')}`;
                                    let fileGroup = locs_list.querySelector(`#${fileGroupId}`);
                                    if (!fileGroup) {
                                        fileGroup = document.createElement('li');
                                        fileGroup.id = fileGroupId;
                                        fileGroup.innerText = `-- ${loc.filepath} --`;
                                        fileGroup.style.marginTop = '10px';
                                        let fileLocsList = document.createElement('ul');
                                        fileLocsList.className = 'file-locs-list';

                                        fileGroup.appendChild(fileLocsList);
                                        locs_list.appendChild(fileGroup);
                                    }
                                    let fileLocsList = fileGroup.querySelector('.file-locs-list');
                                    let loc_li = document.createElement('li');
                                    loc_li.innerText = `${loc.lineNum}: ${loc.content.trim().slice(0, MAX_LOC_CHARS)}`;
                                    loc_li.style.cursor = 'pointer';
                                    let href = `file://${loc.filepath}#${loc.lineNum}:${loc.colNum}`;
                                    loc_li.onclick = (evt) => {
                                        vscode.postMessage({command: "open", is_ctrl_click: evt.ctrlKey, link: href});
                                    };
                                    fileLocsList.appendChild(loc_li);
                                } else {
                                    let loc_li = document.createElement('li');
                                    loc_li.innerText = `${loc.lineNum}: ${loc.content.trim().slice(0, MAX_LOC_CHARS)}`;
                                    loc_li.style.cursor = 'pointer';
                                    let href = `file://${loc.filepath}#${loc.lineNum}:${loc.colNum}`;
                                    loc_li.onclick = (evt) => {
                                        vscode.postMessage({command: "open", is_ctrl_click: evt.ctrlKey, link: href});
                                    };
                                    locs_list.appendChild(loc_li);
                                }
                            }
                            if (func.locs.length > MAX_LOCS_DISPLAY) {
                                let loc_li = document.createElement('li');
                                loc_li.innerText = `...and ${func.locs.length - MAX_LOCS_DISPLAY} more locations. Refine your search to see fewer results.`;
                                locs_list.appendChild(loc_li);
                            }
                            li.appendChild(locs_list)
                        } else {
                            li.style.color = 'red'
                            li.style.display = 'none'
                        }
                    }

                    functions_list.appendChild(li)
                }
                fragment.appendChild(functions_list)

                let end = new Date().getTime()
                console.log(`Time taken to render locations for function: ${(end - start) / 1000} s`)
                


                // append callstacks
                h2 = document.createElement("h2")
                const MAX_NUM_CALLSTACKS = 250
                h2.innerText = `Filtered Callstacks (first ${MAX_NUM_CALLSTACKS})`
                fragment.appendChild(h2)

                let ul = document.createElement('ul')
                ul.innerHTML = message.callstacks.slice(0, MAX_NUM_CALLSTACKS).join("")
                fragment.appendChild(ul)


                // append fragment
                functions_list_container.innerHTML = ""
                functions_list_container.appendChild(fragment)
                AddEventListeners(document.querySelector('#content'))

                // set mark all reviewed button visibility
                document.querySelector('#btn-mark-all-reviewed').disabled = functions.length === 0
                document.querySelector('#btn-bulk-update-decorator').disabled = functions.length === 0

                highlightSearchRegex()

                scrollToTop()

                break;
            case 'showInScopeGraph':
                let graph = message.graph
                if (graph?.nodes?.length > 0) {
                    let scope_graph_container = document.querySelector('#scope-graph-container')
                    scope_graph_container.innerHTML = '<div id="cy-scope-container"></div><div id="cy-scope"></div>'
                    clearCytoscapeInstances("scope")
                    createChart('cy-scope', graph)
                    scope_graph_container.scrollIntoView({behavior: 'smooth', block: 'start'});
                }
                break;
            case 'displayScope': 
                setSelectedScope(message.scope, message.checkbox_ids_to_check)
                break
            case 'displayFunction':
                if (! message.navigated_from_history) {
                    let s = vscode.getState()
                    if (s.function_history_ids.slice(-1)[0] !== message.function.id) {
                        s.function_history_ids.splice(s.function_history_index + 1, Infinity, message.function.id)
                        s.function_history_index = s.function_history_ids.length - 1
                        vscode.setState(s)
                    }
                }

                setSelectedFunction(message.function)
                
                // scrollToTop()
                break
            case 'toggleHelpHTML':
                let help_ele = document.querySelector('#help')
                if (help_ele.innerHTML) {
                    help_ele.innerHTML = ''
                } else {
                    help_ele.innerHTML = `<div><h1>Help</h1>${message.helpHTML}</div>`
                }
                break;
            case 'receiveFuncStateVarReadWriteMapping':
                window.funcStateVarReadWriteMapping = message.mapping
                break;

            case 'setGraph':
                setGraph(message.graph_id, message.graph, message.f_id, message.filename)

                setScope(window.lastScope?.scope?.id, message.graph)
                break;
            case 'setDecoratorUnicode':
                document.querySelector(`#decorator-description-value`).innerText = message.decorator
                break;

            case 'hasNewData':
                if (message.value) {
                    document.getElementById('new-data-state').innerText = "🟠 NEW DATA"
                }
                break;
        }
    });


    return {
        CONSTANTS: {
            doneTypingInterval: doneTypingInterval
        },
        setHighlight: setHighlight,
        highlightSearchRegex: highlightSearchRegex,
        searchFunctions: searchFunctions,
        joinFunctions: joinFunctions,
        last_graph_interacted: window.last_graph_interacted,
        searchFuncMode: window.searchFuncMode,
        AddEventListeners: AddEventListeners,
        setScope: setScope
    }
}());


