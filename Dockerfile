FROM python:3.12-alpine

ENV UV_INSTALL_DIR=/usr/local/bin
RUN wget -qO- https://astral.sh/uv/install.sh | sh
ENV PATH="/usr/local/bin:${PATH}"

WORKDIR /app

COPY pyproject.toml ./
COPY uv.lock ./
COPY .python-version ./
COPY .env ./
COPY README.md ./
COPY src/ ./src/
COPY demo_files/command-injection/important-file-with-integrity.txt ./demo_files/command-injection/important-file-with-integrity.txt

RUN uv venv
RUN uv sync

RUN echo "#!/bin/sh" > ./run-cli.sh
RUN echo "uv run cra_demo_app" >> ./run-cli.sh
RUN chmod +x ./run-cli.sh

ENTRYPOINT ["/app/.venv/bin/pyxtermjs", "--host", "0.0.0.0", "--port", "5000", "--command", "/app/run-cli.sh"]
