FROM python:3.13-slim

RUN addgroup --system raguard && adduser --system --ingroup raguard raguard

WORKDIR /app

COPY pyproject.toml README.md .
COPY src/ src/
RUN pip install --no-cache-dir .

RUN chown -R raguard:raguard /app
USER raguard

ENTRYPOINT ["raguard"]
CMD ["--help"]
