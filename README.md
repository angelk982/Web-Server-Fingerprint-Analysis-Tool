# Web Server Information and Hash Generation Tool

This tool is designed to gather detailed information about a web server, including its technologies, open ports, server response headers, and then generate a SHA-256 hash of this information to create a unique fingerprint. It's Dockerized for easy setup and execution across different environments.

# Prerequisites

Before you begin, ensure you have Docker installed on your system. Docker is available for Windows, macOS, and various Linux distributions. Visit the official Docker documentation to download and install Docker for your platform.

# Setup

   1. Clone the repository: First, clone this repository to your local machine using Git. If Git is not installed, download the ZIP file directly from the repository page.
      git clone https://your-repository-url.git
      cd your-repository-directory

   2. Build the Docker image: Navigate to the directory containing the Dockerfile and run the following command to build the Docker image. This step compiles your Docker image with all the necessary dependencies.
      docker build -t tool .

# Execution

To run the tool, use the following Docker command. You can pass specific arguments to the tool by appending them after the image name. The tool accepts arguments for specifying the URL of the web server to analyze, the type of information to retrieve (--info), and the output format (--output)

docker run tool http://example.com --info "all" --output "json"

# Arguments

    --url: The URL of the web server you wish to analyze.
    --info: The type of information to retrieve. Options are all, web, ports, tech. Default is all.
    --output: The output format. Choose between hash for a SHA-256 hash of the server information or json for raw data. Default is hash.


