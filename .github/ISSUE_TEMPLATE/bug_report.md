---
name: Bug report
about: Create a report to help us improve
title: ''
labels: ''
assignees: ''

---

## Description

[A clear and concise description of what the bug is.]

## General information

- **Open WebUI version**: [Go to Open WebUI → `Settings` → `About` to find out]
- **Tool/function version**: [Go to Open WebUI → `Workspace` → `Tools` or `Functions`  to find out]
- **Open WebUI setup**:
  - **Kernel information**: [Run `uname -a` to find out]
  - **Runtime**: [Docker? Kubernetes? Custom?]
  - If running in Docker:
    - **Docker version**: [Run `docker --version` to find out]
    - **`docker run` command**: [Paste the command-line you are using to run the Open WebUI Docker container]
    - **Docker container info**: [Run `docker inspect openwebui_container_name_here` to find out]

## Debug logs

To get debug logs, please follow these steps:

1. Enable debug logging in the tool or function by changing `self._debug = False` to `self._debug = True` in the code.
2. Reproduce the issue in a new chat session.
3. Download the chat session (triple-dot menu → `Download` → `Export chat (json)`)
4. Attach the resulting `.json` file to this bug report.

## Additional context

[Add any other context about the problem here.]
