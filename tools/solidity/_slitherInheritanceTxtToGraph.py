import json

content = open('./slither_summary_output/inheritance.txt').readlines()

# should add only those in scope? 
scope = []

nodes = []
edges = []

process = True


currentContract = ""
for line in content:
    line = line.strip()
    
    if "Base_Contract -> Immediate_Child_Contracts" in line:
        process = False

    if not process:
        continue

    if line.startswith("+"):
        currentContract = line.split(' ')[1]
        # push node if not exists
        node = { 'classes': 'l1', 'data': { 'id': currentContract, 'title': currentContract }}
        if node not in nodes:
            nodes.append(node)
        continue

    if line.startswith('-> '):
        line = line.replace('-> ', '')
        subContracts = line.split(', ')

        for c in subContracts:
            node = { 'classes': 'l1', 'data': { 'id': c, 'title': c }}
            if node not in nodes:
                nodes.append(node)

            edge = { 'data': { 'source': c, 'target': currentContract } }
            if edge not in edges:
                edges.append(edge)


graph = {
    'nodes': nodes,
    'edges': edges
}

open('./.vscode/graphs/_inheritance.graph', 'w').write(json.dumps(graph))
    
