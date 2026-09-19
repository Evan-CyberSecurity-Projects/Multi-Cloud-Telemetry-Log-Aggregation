FROM python:3.13-slim

WORKDIR /app

COPY src ./src
COPY sample_data ./sample_data

ENTRYPOINT ["python", "-m", "src.cli"]
CMD ["--input-dir", "sample_data", "--output-dir", "output"]
