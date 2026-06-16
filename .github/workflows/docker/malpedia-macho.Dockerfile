FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /work

RUN useradd --create-home --uid 10001 smda

COPY pyproject.toml README.md LICENSE /work/
COPY src /work/src
COPY tests /work/tests
COPY .github/workflows/scripts /work/.github/workflows/scripts

RUN python -m pip install --upgrade pip \
    && python -m pip install -e ".[dev]"

USER smda
