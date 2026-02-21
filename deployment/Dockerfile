FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV VORPAL_HOME=/vorpal_base
ENV VORPAL_APP_SERVER_LISTEN=ws://127.0.0.1:7788
ENV VORPAL_PROXY_TARGET=ws://127.0.0.1:7788
ENV VORPAL_PROXY_LISTEN=0.0.0.0:8000
ENV VORPAL_PROXY_LOG_FILE=/var/log/vorpal/vorpal_proxy.log
ENV VORPAL_AZUREAI_ENDPOINT=https://vigilant-local-eastus2-aoai.cognitiveservices.azure.com/openai/responses?api-version=2025-04-01-preview
ENV HOME=/home/vorpal

RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  git \
  gnupg \
  libdbus-1-3 \
  libsecret-1-0 \
  lsb-release \
  software-properties-common \
  && add-apt-repository -y ppa:deadsnakes/ppa \
  && apt-get update \
  && apt-get install -y --no-install-recommends \
  python3.13 \
  python3.13-venv \
  && ln -sf /usr/bin/python3.13 /usr/local/bin/python \
  && ln -sf /usr/bin/python3.13 /usr/local/bin/python3 \
  && mkdir -p /etc/apt/keyrings \
  && curl -sLS https://packages.microsoft.com/keys/microsoft.asc \
    | gpg --dearmor -o /etc/apt/keyrings/microsoft.gpg \
  && chmod go+r /etc/apt/keyrings/microsoft.gpg \
  && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ $(lsb_release -cs) main" \
    > /etc/apt/sources.list.d/azure-cli.list \
  && apt-get update \
  && apt-get install -y --no-install-recommends azure-cli \
  && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 vorpal \
  && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/vorpal --shell /bin/bash vorpal

WORKDIR /opt/vorpal

COPY codex-rs/target/release/vorpal /usr/local/bin/vorpal
COPY proxy /opt/vorpal/proxy
COPY deployment/requirements.txt /opt/vorpal/deployment/requirements.txt
COPY deployment/skills /vorpal_base/skills
COPY deployment/start-vorpal-app-server.sh /opt/vorpal/deployment/start-vorpal-app-server.sh
COPY deployment/start-vorpal-proxy.sh /opt/vorpal/deployment/start-vorpal-proxy.sh
COPY deployment/start-services.sh /opt/vorpal/deployment/start-services.sh

RUN python3.13 -m ensurepip --upgrade \
  && python3.13 -m pip install --no-cache-dir --upgrade pip \
  && python3.13 -m pip install --no-cache-dir -r /opt/vorpal/deployment/requirements.txt \
  && python3.13 -m pip install --no-cache-dir /opt/vorpal/proxy \
  && mkdir -p /vorpal_base/context /var/log/vorpal /home/vorpal/.azure \
  && chmod +x \
    /opt/vorpal/deployment/start-vorpal-app-server.sh \
    /opt/vorpal/deployment/start-vorpal-proxy.sh \
    /opt/vorpal/deployment/start-services.sh \
    /usr/local/bin/vorpal \
  && chown -R vorpal:vorpal /opt/vorpal /vorpal_base /var/log/vorpal /home/vorpal /usr/local/bin/vorpal

USER vorpal

EXPOSE 8000

CMD ["/opt/vorpal/deployment/start-services.sh"]
