import json

scopes = open('./.vscode/ext-static-analysis/scope_summaries_html.json', 'r').read()
scopes = json.loads(scopes)

scope_names = set([s['name'] for s in scopes])

functions = open('./.vscode/ext-static-analysis/functions_html.json', 'r').read()
functions = json.loads(functions)

# for each scope, search for all functions with that scope_id and collect decorators into a set() where each character is a decorator
for scope in scopes:
    scope_id = scope['id']
    scope_name = scope['name']
    inheritance = scope['inherits'] # list of scope_ids current scope inherits from

    decorators = set()
    for f in functions:
        if f['scope_id'] == scope_id:
            for c in f['decorator']:
                # if c is an ascii character, skip it
                if ord(c) < 128:
                    continue
                decorators.add(c)

    scope['decorators'] = "".join(decorators)





# for scope in scopes:
#     scope_id = scope['id']
#     scope_name = scope['name']
#     inheritance = scope['inherits'] # list of scope_ids current scope inherits from


    # if line.startswith("+"):
    #     currentContract = line.split(' ')[1]
    #     # push node if not exists
    #     node = { 'classes': 'l1', 'data': { 'id': currentContract, 'title': currentContract }}
    #     if node not in nodes:
    #         nodes.append(node)
    #     continue

    # if line.startswith('-> '):
    #     line = line.replace('-> ', '')
    #     subContracts = line.split(', ')

    #     for c in subContracts:
    #         node = { 'classes': 'l1', 'data': { 'id': c, 'title': c }}
    #         if node not in nodes:
    #             nodes.append(node)

    #         edge = { 'data': { 'source': c, 'target': currentContract } }
    #         if edge not in edges:
    #             edges.append(edge)


# build dagre inheritance graph in cytoscapes
def build_inheritance_graph(scopes):
    nodes = []
    edges = []

    for scope in scopes:
        if "mock" in scope['id'].lower():
            continue        

        scope_id = scope['id']
        scope_name = scope['name']
        inheritance = scope['inherits'] # list of scope_ids current scope inherits from

        scopes_with_same_name = [s for s in scopes if s['name'] == scope_name]
        scopes_with_same_name_links = [f"<a href='file://{s['id'].split(',')[1]}'>{index}</a>" for index, s in enumerate(scopes) if s['name'] == scope_name]
        # collect all unique characters from decorators
        all_decorators = set()
        for s in scopes_with_same_name:
            for c in s['decorators']:
                all_decorators.add(c)
        all_decorators = "".join(all_decorators)


        node = { 'classes': 'l1', 'data': { 'id': scope_name, 'type': scope['type'], 'title': f"{scope_name} {all_decorators} {' '.join(scopes_with_same_name_links)}", 'content': "\n".join([f'{s["id"]} {s["decorators"]}' for s in scopes_with_same_name]), 'isCollapsed': True}}
        if node not in nodes:
            nodes.append(node)
        
        # create edge from interface self to self
        interface_scope_name = f"I{scope_name}"
        if interface_scope_name in scope_names:
            edge = { 'data': { 'source': interface_scope_name, 'target': scope_name } }
            if edge not in edges:
                edges.append(edge)


        for parent in inheritance:
            parent_name = parent.split(',')[0]
            edge = { 'data': { 'source': parent_name, 'target': scope_name } }
            if edge not in edges:
                edges.append(edge)


    graph = {
        'nodes': nodes,
        'edges': edges
    }

    return graph

graph = build_inheritance_graph(scopes)

# remove all nodes from graph that are not listed as an edge
def remove_unconnected_nodes(graph):
    nodes = graph['nodes']
    edges = graph['edges']

    connected_nodes = []
    for edge in edges:
        connected_nodes.append(edge['data']['source'])
        connected_nodes.append(edge['data']['target'])

    connected_nodes = list(set(connected_nodes))

    new_nodes = []
    for node in nodes:
        if node['data']['id'] in connected_nodes or node['data']['type'] == 'contract':
            new_nodes.append(node)

    graph['nodes'] = new_nodes

    return graph

graph = remove_unconnected_nodes(graph)



with open('./.vscode/ext-static-analysis/graphs/inheritance_graph.json', 'w') as f:
    f.write(json.dumps(graph))
