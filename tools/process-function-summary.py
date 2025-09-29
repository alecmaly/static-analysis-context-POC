import debugpy
import json
import re


# hide "internal" visibility
# Array.from(document.querySelectorAll('tr')).forEach(row => { if (row.children[2].innerText == 'internal') row.style.display = 'none' })

output = """
<html>
    <head>
        <title>Functions</title>
    </head>
    <body>
        <style>
            table, th, td {
                border: 1px solid black;
                border-collapse: collapse;
                text-align: center;
                padding-left: 2px;
                padding-right: 2px;
            }
        </style>
"""


all_contracts = []
output_body = ""
in_contract = ""
contract_vars = ""
state = None  # TableHeader | TableBody 
lines = open('function-summary.txt', 'r').readlines()

i = 0
while i < len(lines): 
    line = lines[i].strip()
    if line.startswith("Contract") and not line.startswith("Contract vars:"):
        contract_name = " ".join(line.split(' ')[1:])
        output_body += f"<br><div id='{contract_name}' class='contract'>Contract: <b>{contract_name}</b></div>\n"
        in_contract = contract_name

    if line.startswith("Contract vars:"):
        output_body += f"<div class='contract-vars'>{line}</div>\n"
        contract_vars = int(line.count("'")/2)

    if line.startswith("Inheritance:"):
        output_body += f"<div class='contract-inheritance'>{line}</div>"
        all_contracts.append({'contract': in_contract, 'inheritance': f"{line}", 'inherited_count': int(line.count("'")/2), 'contract_vars_count': contract_vars})

    is_table = re.search("\+-+\+-+\+-+\+-+\+-+\+-+\+-+\+", line)

    if is_table:
        if state == None:
            state = "TableHeader"
            output_body += "<table>"
        elif state == "TableHeader":
            state = "TableBody"
        elif state == "TableBody":
            state = None
            output_body += "</table>"
        i += 1
        continue

    if state == "TableHeader":
        headers = [cell.strip() for cell in line.split("|")]
        output_body += f"""<tr><th>{"</th><th>".join(headers)}</th></tr>"""

    if state == "TableBody":
        cells = [cell.strip() for cell in line.split("|")]

        # loop all next lines and collect output_body if still current function
        nextI = 1
        while True:
            next_line_cells = [cell.strip() for cell in lines[i + nextI].split("|")]
            nextI += 1
            
            # break if next line is end of table or has a visibility
            if len(next_line_cells) != len(headers) or next_line_cells[2] != "": 
                break
            else:
                # next line is continuation, merge/combine w/ current line
                cells = [a+b for a, b in zip(cells, next_line_cells)]
        i += nextI - 2
        
        output_body += f"""<tr><td>{"</td><td>".join(cells)}</td></tr>"""
    i += 1

        # for cell in line.strip().split("|"):
        #     print(cell.strip())





controls_body = """
<style>
.navbar {
  overflow: hidden;
  background-color: #333;
  position: sticky;
  top: 0;
}

.navbar a {
  float: left;
  color: white;
  text-align: center;
  padding: 14px 16px;
  text-decoration: none;
  font-size: 17px;
}

.navbar a:hover {
  background-color: #ddd;
  color: black;
}

.settings {
  float: right;
}
</style>

<script>
window.onscroll = function() {stickyNav()};

var navbar = document.querySelector(".navbar");
var sticky = navbar.offsetTop;

function stickyNav() {
  if (window.pageYOffset >= sticky) {
    navbar.classList.add("sticky");
  } else {
    navbar.classList.remove("sticky");
  }
}
</script>


<div class="navbar">
  <a href="#">Home</a>
  <a><button onclick="hidePrivateInternal()">Hide Private/Internal</button><br><button onclick="showPrivateInternal()">Show Private/Internal</button></a>
  <a><button onclick="hidePublicExternal()">Hide Public/External</button><br><button onclick="showPublicExternal()">Show Public/External</button></a>
  <a>val min:<input id='num_val_min' type='number' onkeyup="filterTableOfContents()" onchange="filterTableOfContents()"><br>inherited min:<input id='num_inherited_min' type='number' onkeyup="filterTableOfContents()" onchange="filterTableOfContents()"></a>
  <a href="#">Contact</a>
  <a class="settings" href="#">Settings</a>
</div>




<script>
    function hidePrivateInternal() {
        hideVisibility('internal')
        hideVisibility('private')        
    }
    function showPrivateInternal() {
        showVisibility('internal')
        showVisibility('private')        
    }

    function hidePublicExternal() {
        hideVisibility('public')
        hideVisibility('external')        
    }
    function showPublicExternal() {
        showVisibility('public')
        showVisibility('external')        
    }
    
    function hideVisibility(visibility) {
        Array.from(document.querySelectorAll('tr')).forEach(row => { if (row.children[2].innerText == visibility) row.style.display = 'none' })
    }
    function showVisibility(visibility) {
        Array.from(document.querySelectorAll('tr')).forEach(row => { if (row.children[2].innerText == visibility) row.style.display = '' })
    }

    function filterTableOfContents() {
        let num_val_min = parseInt(document.querySelector('#num_val_min').value)
        let num_inherited_min = parseInt(document.querySelector('#num_inherited_min').value)
        Array.from(document.querySelectorAll('.contract')).forEach(ele => { 
            if (parseInt(ele.getAttribute('num_val')) < num_val_min || parseInt(ele.getAttribute('num_inherited')) < num_inherited_min) 
                ele.style.display = 'none' 
            else
                ele.style.display = '' 
        })
    }

    
</script>
"""


table_of_contents = "Table of Contents<br>"
for c in all_contracts:
    table_of_contents += f"<div class='contract' num_val={c['contract_vars_count']} num_inherited={c['inherited_count']}><a href='#{c['contract']}'>{c['contract']}</a> - (V:{c['contract_vars_count']} | I:{c['inherited_count']}) {c['inheritance']}</div>"

open('output_data.html', 'w').write(output + controls_body + table_of_contents + output_body)