# Development guide

This repository implements an Open WebUI tool and function for code execution.
**Open WebUI tools and functions must be distributed as standalone,
self-contained files**. However, the code for the tool and the function has
grown beyond what can reasonably fit in a single file. Additionally, a lot
of the code is shared between the tool and the function, since both of them
are fundamentally similar in that they must execute code and report its
status to Open WebUI. It is unwieldy to maintain multiple copies of this code
within very large files.

To mitigate these problems, this repository is organized as follows:

```
🌲 safe-code-execution
├── 🍝 src
│   ├── 📂 safecode
│   │   └── 🐍 # Python modules to facilitate execution of sandboxed code.
│   └── 📂 openwebui
│       ├── 📂 functions
│       │   │   # In-repo runnable version of the Open WebUI code execution function:
│       │   └── 🐍 run_code.py  
│       ├── 📂 tools
│       │   │   # In-repo runnable version of the Open WebUI code execution tool:
│       │   └── 🐍 run_code.py
│       └── 🐍 # Other Python modules that are reusable across Open WebUI extensions.
├── 🚢 open-webui
│   ├── 📂 functions
│   │   │   # Self-contained version of the Open WebUI code execution function:
│   │   └── ⚙️ run_code.py
│   └── 📂 tools
│       │   # Self-contained version of the Open WebUI code execution tool:
│       └── ⚙️ run_code.py
├── 🏗️ build
│   │   # Script to generate the contents of `🚢 /open-webui`:
│   └── 🐍 build_openwebui.py
├── 🧪 tests
│   └── 📂 open-webui
│       ├── 📂 functions
│       │   │   # Execute self-tests for open-webui/functions/run_code.py:
│       │   └── 📜 run_code_tests.sh
│       └── 📂 tools
│           │   # Execute self-tests for open-webui/tools/run_code.py:
│           └── 📜 run_code_tests.sh
└── ❓ docs
    │   # This document:
    └── 📃 dev.md
```

When users want to install the Open WebUI code execution function or tool,
they can simply use the file directly in `🚢 /open-webui`.

However, when developing on this extension, you should only modify files in
`🍝 /src`. Then when creating pull requests, ensure that you have refreshed the
files in `🚢 /open-webui` by running the appropriate script in `🏗️ /build`.
