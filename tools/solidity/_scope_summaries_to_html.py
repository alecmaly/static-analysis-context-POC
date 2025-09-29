import json

scope_summaries = json.loads(open('./.vscode/ext-static-analysis/scope_summaries_html.json').read())

#  cat ./.vscode/scope_summaries.html |grep -oE ">[^<]*?\.[^<]*? = " | rev | cut -d'.' -f1 | rev | uniq -c | sort -n

html_output = """
<script src="https://cdn.jsdelivr.net/npm/mark.js/dist/mark.min.js"></script>

<style>
    header {
        background-color: #333;
        color: white;
        padding: 10px 0;
        text-align: center;
        position: -webkit-sticky; /* For Safari */
        position: sticky;
        top: 0; /* This ensures it sticks to the top */
        z-index: 1000; /* This ensures it stays on top of other content */
    }
    input[type='text'] {
        min-width: 20em;
    }
</style>

<header>
    <input id='filter-regex'type='text' placeholder='filter regex'></input>
    <input id='exclude-regex' type='text' placeholder='exclude regex'></input>
    <button id='toggle-vars' value='visible'>Showing Vars</button>
    <button id='toggle-modifiers' value='visible'>Showing Modifiers</button>
    <button id='toggle-functions' value='visible'>Showing Functions</button>
</header>

<script>
    document.querySelector('#toggle-vars').addEventListener('click', function(evt) {
        evt.target.value = evt.target.value === 'visible' ? 'hidden' : 'visible'
        evt.target.innerText = evt.target.value === 'hidden' ? 'Hiding Vars' : 'Showing Vars'
        document.querySelectorAll('.state_vars_html').forEach(ele => { ele.style.display = evt.target.value === 'visible' ? 'block' : 'none' })
    })

    document.querySelector('#toggle-modifiers').addEventListener('click', function(evt) {
        evt.target.value = evt.target.value === 'visible' ? 'hidden' : 'visible'
        evt.target.innerText = evt.target.value === 'hidden' ? 'Hiding Modifiers' : 'Showing Modifiers'
        document.querySelectorAll('.modifiers_html').forEach(ele => { ele.style.display = evt.target.value === 'visible' ? 'block' : 'none' })
    })

    document.querySelector('#toggle-functions').addEventListener('click', function(evt) {
        evt.target.value = evt.target.value === 'visible' ? 'hidden' : 'visible'
        evt.target.innerText = evt.target.value === 'hidden' ? 'Hiding Functions' : 'Showing Functions'
        document.querySelectorAll('.functions_html').forEach(ele => { ele.style.display = evt.target.value === 'visible' ? 'block' : 'none' })
    })


    let globalTimerTimeout = 700
    let globalTimer
        
    function applyFilters() {
        let containers = document.querySelectorAll('.summary-content')
        let filter_regex = document.querySelector('#filter-regex').value
        let exclude_regex = document.querySelector('#exclude-regex').value
        
        for (let container of containers) {
            let subcontainers = ['state_vars_html', 'modifiers_html', 'functions_html']
            
            let hasContent = false
            for (let subcontainer of subcontainers) {
                for (let subcontainer_ele of container.querySelectorAll(`.${subcontainer}`)) {
                    for (let ele of subcontainer_ele.querySelectorAll('div,span')) {
                        let filter_regex_exp = new RegExp(filter_regex, 'i')
                        let exclude_regex_exp = new RegExp(exclude_regex, 'i')
                
                        if (exclude_regex && ele.innerText.match(exclude_regex_exp)) {
                            ele.style.display = 'none'
                            continue
                        }
                
                        if (ele.innerText.match(filter_regex_exp)) {
                            ele.style.display = 'block'
                            hasContent = true
                        } else {
                            ele.style.display = 'none'
                        }

                    }
                }
            }
            container.style.display = hasContent ? 'block' : 'none'
        }



        var context = document.body;

        // Create a new instance of Mark.js for the selected context.
        var instance = new Mark(context);

        instance.unmark()

        // Define a regular expression. For example, to match any word starting with "te".
        var regex = new RegExp(filter_regex, "gi");

        // Use the markRegExp() method to highlight text matching the regex pattern.
        instance.markRegExp(regex);

    }


    document.querySelector('#filter-regex').addEventListener('keyup', function(evt) {
        globalTimer = setTimeout(applyFilters, globalTimerTimeout)
    })
    document.querySelector('#exclude-regex').addEventListener('keyup', function(evt) {
        globalTimer = setTimeout(applyFilters, globalTimerTimeout)
    })

    applyFilters()

</script>
"""

keys = ['state_vars_html', 'modifiers_html', 'functions_html']
for scope_summary in scope_summaries:
    if "\\ud83c\\udfaf" not in json.dumps(scope_summary): # 🎯
        continue

    html_output += f"<h2 class='sticky-scroll-header' style='background-color: lightgray'>{scope_summary['id']}</h2>"
    html_output += "<div class='summary-content'>" 


    for key in [key for key in keys]:
        html_output += f"<h3>{key}</h3>"
        # html_output += f"<div class='{key}'>{scope_summary[key].replace('<br>', '')}</div>"
        html_output += f"<div class='{key}'>{scope_summary[key]}</div>"
    html_output += "</div>"


    print(scope_summary['id'])


html_output += """

<script>
    async function run() {
        async function waitForElementToDisplay(selector) {
            return new Promise(resolve => {
                const intervalId = setInterval(() => {
                    const element = document.querySelector(selector);
                    if (element) {
                        clearInterval(intervalId);
                        resolve(element);
                    }
                }, 100);
            });
        }

        function setStickyHeaders() {
            let files = Array.from(document.querySelectorAll('.sticky-scroll-header')).filter(row => { return row.checkVisibility() });
            let lastVisibleIndex = files.length - 1;
            
            function updateLastVisibleElement() {
                let files = Array.from(document.querySelectorAll('.sticky-scroll-header')).filter(row => { return row.checkVisibility() });
                let top_offset = document.querySelector('header').getBoundingClientRect().bottom - document.querySelector('header').getBoundingClientRect().top
        
                for (let i = files.length - 1; i >= 0; i--) {
                    let rect = files[i].getBoundingClientRect();
                    if (rect.top <= top_offset) { //  && rect.top < files[lastVisibleIndex].getBoundingClientRect().top
                        if (i === lastVisibleIndex)
                            break
                        
                        if (lastVisibleIndex >= 0) {
                            files[lastVisibleIndex].style.position = '';
                            files[lastVisibleIndex].style.top = '';
                        }
        
                        files[i].style.position = 'sticky';
                        files[i].style.top = `${top_offset}px`;
                        lastVisibleIndex = i;
                        break;
                    }
                }
            }
            
            window.addEventListener('scroll', updateLastVisibleElement);
            window.addEventListener('resize', updateLastVisibleElement);
        }
        
        await waitForElementToDisplay('header')
        setStickyHeaders()
    }

    run()
</script>


"""

open('./.vscode/_scope_summaries.html', 'w').write(html_output)