FROM python:3.13

# Set the working directory inside the container
WORKDIR /cy_project

# Install OpenGL dependencies (for OpenCV)
RUN apt-get update && apt-get install -y libgl1 libglib2.0-0

# Copy the project files
COPY . /cy_project/

# Upgrade pip and install dependencies
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Run the application (ensure scripts execute properly)
CMD ["sh", "-c", "python server_boot.py && python test_start.py"]
