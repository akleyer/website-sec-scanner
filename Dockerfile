# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the Python script into the container at /usr/src/app
COPY ssl_scan.py .

# Copy the requirements file into the container at /usr/src/app
# Assuming you have a requirements.txt file with the necessary libraries
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Run ssl_scan.py when the container launches
ENTRYPOINT ["python", "./ssl_scan.py"]
