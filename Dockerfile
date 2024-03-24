# Use an official Alpine-based Python image
FROM python:3.9-alpine

# Set the working directory in the container
WORKDIR /app

# Install dependencies required for nmap and other build processes
RUN apk add --no-cache gcc musl-dev linux-headers nmap nmap-scripts

# Copy the current directory contents into the container at /app
COPY . .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Specify the entry point of the container
ENTRYPOINT ["python", "./FingerprintAnalysisTool.py"]
