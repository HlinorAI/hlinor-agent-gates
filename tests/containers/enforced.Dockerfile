FROM ubuntu:24.04
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d && apt-get update && apt-get install -y --no-install-recommends git python3 python3-pytest sudo openssh-client procps passwd util-linux findutils cron at e2fsprogs && rm -rf /var/lib/apt/lists/*
ENV PYTHONDONTWRITEBYTECODE=1
