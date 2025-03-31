FROM python:3.13

WORKDIR /cy_project

COPY requirements.txt /cy_project/

RUN pip install --no-cache-dir -r requirements.txt

COPY . /cy_project/

CMD ["sh", "-c", "python server_boot.py && python test_start.py"]
