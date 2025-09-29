# Load into solhint

1. From this project run:

```bash
npm link
```

2. Install custom rules: From project where you will run solhint 

```bash
# npm link <package_name>
npm link solhint-plugin-customRuleset
```

3. Create configs

`.solhintignore`
```
lib/
libs/
libraries/
node_modules/
interfaces/
test/
mocks/
```

`.solhint.json`
```json
{
  "plugins": ["customRuleset"],
  "rules": {
    "customRuleset/no-foos": "error",
    "customRuleset/no-bars": "error",
    "customRuleset/dump-ast": "error"
  }
}
```

3. Run solhint

```bash
solhint ./*.sol -f unix

# run program to convert to detector-results.json
# + move to .vscode folder
## TO DO: create script



npm link solhint-plugin-customRuleset       # import custom plugin
rm solhint_output.txt                       # remove previous output file
find ./ -name "*.sol" -type f |xargs -I{} -P3 sh -c 'solhint {} -c .solhint.json -f unix -c >>  solhint_output.txt'  # run solhint
python3 solhint-to-detector-results.py       # convert + move to .vscode
```

