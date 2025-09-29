import json

filepath = './.vscode/detector-results.json'

data = json.loads(open(filepath).read())

# strip out all but the first line of each 'lines' array
def update_lines(obj):
    if isinstance(obj, dict):
        for key in obj:
            if key == 'lines':
                obj[key] = [obj[key][0]]
            else:
                update_lines(obj[key])
    elif isinstance(obj, list):
        for i in range(len(obj)):
            update_lines(obj[i])

for row in data:
    update_lines(row)


open(filepath, 'w').write(json.dumps(data))


