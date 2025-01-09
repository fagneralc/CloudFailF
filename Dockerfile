FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

RUN mkdir -p data && \
    chmod +x cloudfail.py

ENV $(cat .env | xargs)

ENTRYPOINT ["python", "cloudfail.py"]
CMD ["--help"]
