# Disposable environment for the release gate: Node for the agents, Python for the API stub and probes.
FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates git bubblewrap socat && rm -rf /var/lib/apt/lists/*
RUN useradd -m dev
ENV NPM_CONFIG_PREFIX=/opt/agents DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
ENV PATH=/opt/agents/bin:$PATH
RUN mkdir -p /opt/agents && chown dev /opt/agents
