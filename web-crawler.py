import requests  # Importing the requests library for making HTTP requests
from bs4 import BeautifulSoup  # Importing BeautifulSoup for HTML parsing
import argparse  # Importing argparse for command-line argument parsing
from urllib.parse import urljoin, urlparse  # Importing urllib.parse for URL manipulation
from pathlib import Path  # Importing pathlib for working with file paths
import urllib3  # Importing urllib3 to disable SSL warnings
import sys  # Importing sys for system-specific parameters and functions

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Disable SSL warnings

file_urls = {
    "Html": {"count": 0, "size": 0, "urls": [], "sizes": []},
    "Css": {"count": 0, "size": 0, "urls": [], "sizes": []},
    "Jpg": {"count": 0, "size": 0, "urls": [], "sizes": []},
    "Js": {"count": 0, "size": 0, "urls": [], "sizes": []},
    "Png": {"count": 0, "size": 0, "urls": [], "sizes": []},
    "Gif": {"count": 0, "size": 0, "urls": [], "sizes": []},
    "Asp": {"count": 0, "size": 0, "urls": [], "sizes": []},
    "Other": {"count": 0, "size": 0, "urls": [], "sizes": []},
}

visited_urls = set()  # Set to keep track of visited URLs


def get_file_type(url):
    parsed_url = urlparse(url)
    path = parsed_url.path
    file_extension = Path(path).suffix.lower()

    if file_extension == ".html":
        return "Html"
    elif file_extension == ".css":
        return "Css"
    elif file_extension == ".jpg":
        return "Jpg"
    elif file_extension == ".js":
        return "Js"
    elif file_extension == ".png":
        return "Png"
    elif file_extension == ".gif":
        return "Gif"
    elif file_extension == ".asp":
        return "Asp"
    else:
        return "Other"



def write_output(recursion_level, output_file):
    """
    Writes the output to a file or prints it to the console.
    """
    output = f"At recursion level {recursion_level}\n"#prints "At recursion level-whatever is specified"
    output += f"Total files found: {sum([file_info['count'] for file_info in file_urls.values()])} files  file-size={sum([file_info['size'] for file_info in file_urls.values()])} bytes\n"
    #prints the count and total size of all the files found

    sorted_file_urls = sorted(file_urls.items(), key=lambda x: x[1]['count'])#gives output of html,css,jpg,js sorted according to ascending order of their count
    for file_type, file_info in sorted_file_urls:
        output += f"{file_type}: {file_info['count']} files  file-size={file_info['size']} bytes\n"
        #prints the output filetype name along with its count and size 

        sorted_links = sorted(zip(file_info['urls'], file_info['sizes']), key=lambda x: x[1])
        #sorts links of a particular type in ascending order of their sizes
        for link, size in sorted_links:
            output += f"{link} file-size={size} bytes\n"
        #Within the loop, the code retrieves the URL (link) and size (size) from each tuple and appends a formatted string to the output variable. This string contains the URL followed by the file size in bytes. The \n character represents a newline, ensuring that each URL and size combination is printed on a new line in the output.
        

    if output_file is not None:
        with open(output_file, "w") as file:
            file.write(output)  # Write the output to the specified file
    else:
        print(output)  # Print the output to the console

    return output


def normalize_url(url):
    """
    Normalize the URL by removing the "http://" or "https://" prefix.
    """
    if url.startswith("http://"):
        return url[len("http://"):]  # Remove the "http://" prefix
    elif url.startswith("https://"):
        return url[len("https://"):]  # Remove the "https://" prefix
    return url


def get_file_size(url):
    """
    Returns the size of the file specified by the URL by sending a GET request.
    """
    try:
        response = requests.get(url, verify=False)  # Send a GET request to the URL
        size = len(response.content)  # Get the length of the response content (file size)
        return size
    except:
        return 0  # Return 0 if there was an error retrieving the file size



def scrape(site, base_url, depth, recursion_level, output_file):
    """
    Recursively crawls the website, extracts file URLs, and updates file_urls dictionary.
    """
    site = site.strip()

    if depth is not None and recursion_level > depth:
        return  # Return if the recursion level exceeds the specified depth

    normalized_site = normalize_url(site)
    if normalized_site in visited_urls:
        return  # Return if the site has already been visited

    visited_urls.add(normalized_site)  # Add the site to the visited URLs set

    # Skip URLs containing "googletagmanager.com"
    parsed_url = urlparse(site)
    if "googletagmanager.com" in parsed_url.netloc:
        return  # Return if the URL contains "googletagmanager.com"

    try:
        response = requests.get(site, verify=False)  # Send a GET request to the site
        soup = BeautifulSoup(response.text, "html.parser")  # Create a BeautifulSoup object for HTML parsing
    except (requests.exceptions.InvalidSchema, requests.exceptions.SSLError):
        # Skip URLs with an invalid schema or SSL error
        return

    for tag in soup.find_all():
        if "href" in tag.attrs:
            url = tag["href"]
            if url and not url.startswith(('http://', 'https://')):
                url = urljoin(base_url, url)  # Join the base URL with the relative URL
            url = url.lower().rstrip("/")  # Convert the URL to lowercase and remove trailing slashes
            file_type = get_file_type(url)  # Get the file type based on the URL
            if url and url not in file_urls[file_type]['urls']:
                file_urls[file_type]['urls'].append(url)  # Add the URL to the file_urls dictionary
                file_urls[file_type]['count'] += 1  # Increment the count for the file type
                size = get_file_size(url)  # Get the size of the file
                file_urls[file_type]['size'] += size  # Add the size to the total size for the file type
                file_urls[file_type]['sizes'].append(size)  # Append the size to the sizes list for the file type

                # Check if the opposite scheme (http or https) of the URL is already visited
                opposite_scheme_url = (
                    url.replace("http://", "https://")
                    if url.startswith("http://")
                    else url.replace("https://", "http://")
                )
                opposite_scheme_url = normalize_url(opposite_scheme_url)
                if opposite_scheme_url in visited_urls:
                    continue
                scrape(url, base_url, depth, recursion_level + 1, output_file)  # Recursively scrape the URL
        if "src" in tag.attrs:
            url = tag["src"]
            if url and not url.startswith(('http://', 'https://')):
                url = urljoin(base_url, url)  # Join the base URL with the relative URL
            url = url.lower().rstrip("/")  # Convert the URL to lowercase and remove trailing slashes
            file_type = get_file_type(url)  # Get the file type based on the URL
            if url and url not in file_urls[file_type]['urls']:
                file_urls[file_type]['urls'].append(url)  # Add the URL to the file_urls dictionary
                file_urls[file_type]['count'] += 1  # Increment the count for the file type
                size = get_file_size(url)  # Get the size of the file
                file_urls[file_type]['size'] += size  # Add the size to the total size for the file type
                file_urls[file_type]['sizes'].append(size)  # Append the size to the sizes list for the file type

                # Check if the opposite scheme (http or https) of the URL is already visited
                opposite_scheme_url = (
                    url.replace("http://", "https://")
                    if url.startswith("http://")
                    else url.replace("https://", "http://")
                )
                opposite_scheme_url = normalize_url(opposite_scheme_url)
                if opposite_scheme_url in visited_urls:
                    continue
                scrape(url, base_url, depth, recursion_level + 1, output_file)  # Recursively scrape the URL



def main():
    parser = argparse.ArgumentParser()  # Create an ArgumentParser object
    parser.add_argument("-u", "--url", help="Base URL to crawl", required=True)  # Add an argument for the base URL
    parser.add_argument("-t", "--depth", type=int, help="Depth of recursion", metavar="THRESHOLD")  # Add an argument for the depth of recursion
    parser.add_argument("-o", "--output", help="Output file")  # Add an argument for the output file
    args = parser.parse_args()  # Parse the command-line arguments

    base_url = args.url  # Get the base URL from the command-line arguments
    depth = args.depth  # Get the depth of recursion from the command-line arguments
    output_file = args.output  # Get the output file from the command-line arguments

    if depth is not None and depth <= 0:
        sys.exit("Error: Threshold must be greater than 0.")  # Exit with an error message if the depth is invalid

    scrape(base_url, base_url, depth, 1, output_file)  # Start the scraping process
    output = write_output(depth, output_file)  # Write the output

if __name__ == "__main__":
    main()  # Call the main function if the script is run directly
