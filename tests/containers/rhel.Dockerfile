FROM fedora:43
RUN dnf install -y git python3 sudo openssh-clients procps-ng shadow-utils util-linux findutils cronie at && dnf clean all
ENV PYTHONDONTWRITEBYTECODE=1
