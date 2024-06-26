# Web Server Information and Hash Generation Tool

This tool is designed to gather detailed information about a web server, including its technologies, open ports, server response headers, and then generate a SHA-256 hash of this information to create a unique fingerprint. It's Dockerized for easy setup and execution across different environments.

## Prerequisites

Before you begin, ensure you have Docker installed on your system. Docker is available for Windows, macOS, and various Linux distributions. Visit the [official Docker documentation](https://docs.docker.com/get-docker/) to download and install Docker for your platform.

## Setup

### 1. Clone the Repository

First, clone this repository to your local machine using Git. If Git is not installed, download the ZIP file directly from the repository page.

```bash
git clone https://github.com/angelk982/Web-Server-Fingerprint-Analysis-Tool.git
```
```bash
cd Web-Server-Fingerprint-Analysis-Tool
```
### 2. Build the Docker Image

Navigate to the directory containing the Dockerfile and run the following command to build the Docker image. This step compiles your Docker image with all the necessary dependencies.

```bash
docker build -t tool .
```
This command builds an image named tool based on the Dockerfile in the current directory.

## Execution
To run the tool, use the following Docker command. You can pass specific arguments to the tool by appending them after the image name. The tool accepts arguments for specifying the URL of the web server to analyze, the type of information to retrieve (--info), and the output format (--output).

```bash
docker run tool http://example.com --info all --output json
```
### Arguments
- **`--url`** - The URL of the web server you wish to analyze.
- **`--info`** - The type of information to retrieve. Options are `all`, `web`, `ports`, `tech`. Default is `all`.
- **`--output`** - The output format. Choose between `hash` for a SHA-256 hash of the server information or `json` for raw data. Default is `hash`.

