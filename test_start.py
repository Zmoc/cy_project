import subprocess

# Start multiple programs concurrently
process1 = subprocess.Popen(["python", "server_start.py"])
process2 = subprocess.Popen(["python", "client_start.py"])

# Optionally wait for the processes to finish
process1.wait()
process2.wait()

print("Both scripts have completed.")
