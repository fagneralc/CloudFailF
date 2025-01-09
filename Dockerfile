FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

RUN mkdir -p data
RUN chmod +x cloudfail.py

ENTRYPOINT ["python", "cloudfail.py"]
CMD ["--help"]
