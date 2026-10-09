FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git python3 sudo openssh-client procps passwd util-linux && rm -rf /var/lib/apt/lists/*
ENV PYTHONDONTWRITEBYTECODE=1
