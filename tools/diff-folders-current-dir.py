import os
import hashlib
import multiprocessing

# this will diff all folders in curernt directory and output an .html file to show unique files in each folder


# Function to calculate the MD5 checksum for a file
def calculate_md5(file_path):
    try:
        with open(file_path, 'rb') as file:
            return hashlib.md5(file.read()).hexdigest()
    except Exception as e:
        return None

# Function to find unique files and count their occurrences in folders
def find_unique_files(folder):
    unique_files = {}
    for root, _, files in os.walk(folder):
        for file in files:
            file_path = os.path.join(root, file)
            md5_checksum = calculate_md5(file_path)
            if md5_checksum:
                unique_files.setdefault(md5_checksum, []).append(file_path)
    return unique_files

def generate_html_report(unique_files):
    # Create the HTML header
    html_report = "<html><head><title>Unique Files Report</title></head><body>"

    # Sort unique files by the number of occurrences (reverse order)
    sorted_unique_files = sorted(unique_files.items(), key=lambda x: len(x[1]))

    # Add unique files to the HTML report
    html_report += "<h2>Unique Files and Their Occurrences in Folders:</h2>"
    html_report += "<table>"
    html_report += "<tr><th>File</th><th>Count</th><th>Found in Folders</th></tr>"

    for md5_checksum, file_paths in sorted_unique_files:
        html_report += "<tr>"
        html_report += f"<td>{os.path.basename(file_paths[0])}</td>"
        html_report += f"<td>{len(file_paths)}</td>"
        html_report += f"<td>{', '.join([os.path.dirname(fp) for fp in file_paths])}</td>"
        html_report += "</tr>"

    html_report += "</table>"

    # Close the HTML file
    html_report += "</body></html>"

    with open("unique_files_report.html", "w") as report_file:
        report_file.write(html_report)

if __name__ == '__main__':
    # Get a list of subdirectories in the current directory
    current_dir = os.getcwd()
    subdirectories = [f for f in os.listdir(current_dir) if os.path.isdir(os.path.join(current_dir, f))]

    # Create a list of all subdirectories to search for unique files
    search_directories = [os.path.join(current_dir, sub_dir) for sub_dir in subdirectories]

    # Number of parallel processes to use
    num_processes = multiprocessing.cpu_count()

    with multiprocessing.Pool(processes=num_processes) as pool:
        results = pool.map(find_unique_files, search_directories)

    # Combine results from multiple processes
    unique_files = {}
    for result in results:
        for md5_checksum, file_paths in result.items():
            if md5_checksum in unique_files:
                unique_files[md5_checksum].extend(file_paths)
            else:
                unique_files[md5_checksum] = file_paths

    # Generate the HTML report
    generate_html_report(unique_files)

    print("Unique files report generated: unique_files_report.html")
