// worker.js
const { parentPort, workerData } = require('worker_threads');

const { chunk, functionDefinitionsMap, scopeDefinitionsMap, includedFunctionIds } = workerData;

const localNodes     = [];
const localEdges     = [];
const seenNodes      = new Set();
const seenEdges      = new Set();

for (const cs of chunk) {
  for (let i = 0; i < cs.length - 1; i++) {
    const [caller_f_id, callee_f_id] = [cs[i], cs[i+1]];
    if (!includedFunctionIds[caller_f_id] && !includedFunctionIds[callee_f_id]) continue;

    const caller = functionDefinitionsMap.get(caller_f_id);
    const callee = functionDefinitionsMap.get(callee_f_id);
    if (!caller?.scope_id || !callee?.scope_id) continue;
    
    const callerScope = scopeDefinitionsMap[caller.scope_id];
    const calleeScope = scopeDefinitionsMap[callee.scope_id];

    if (!seenNodes.has(caller_f_id)) {
      seenNodes.add(caller_f_id);
      localNodes.push({ classes: 'l1', data: {
        id: callerScope.id, title: callerScope.name, content: ''
      }});
    }
    if (!seenNodes.has(callee_f_id)) {
      seenNodes.add(callee_f_id);
      localNodes.push({ classes: 'l1', data: {
        id: calleeScope.id, title: calleeScope.name, content: ''
      }});
    }

    const edgeId = `${callerScope.id}-${calleeScope.id}`;
    if (!seenEdges.has(edgeId)) {
      seenEdges.add(edgeId);
      localEdges.push({
        data: { source: callerScope.id, target: calleeScope.id }
      });
    }
  }
}

parentPort.postMessage({ nodes: localNodes, edges: localEdges });
