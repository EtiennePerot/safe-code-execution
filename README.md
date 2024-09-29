# Code execution for Open WebUI

Sandboxed code execution capabilities for [Open WebUI](https://openwebui.com/).

Uses [gVisor](https://gvisor.dev) for secure sandboxing, [as ChatGPT does](https://drive.google.com/file/d/1jjqrV76-86rdEcmFNnxMs4lI-ncAookn/view?resourcekey).

## Function? Tool? Which one do I want?

Open WebUI addons come in multiple types. For code execution, this repository contains both a **code execution function** and a **code execution tool**.

You can install both.

| **Code execution function** | **Code execution tool** |
| --------------------------- | ----------------------- |
| ![Code execution function](https://github.com/EtiennePerot/safe-code-execution/blob/master/res/code-execution-function.gif?raw=true) | ![Code execution tool](https://github.com/EtiennePerot/safe-code-execution/blob/master/res/code-execution-tool.gif?raw=true) |
| Click button to run code block. | Grant the LLM the ability to run code by itself. |

## Code execution function

The **code execution function** shows up as a button under LLM-generated messages. When you click it, the code in the code block of this message will execute. The output is shown in the UI, and is also available to the LLM for further querying.

### Function: How to install

First, [**set up Open WebUI for sandboxing**](docs/setup.md).

Then, in Open WebUI:

* Go to `Workspace` → `Functions`.
* Click the `+`.
* Input the following:
    * **Function name**: `Run code`
    * **Function description**: `Run arbitrary code safely in a gVisor sandbox.`
    * Replace the **code section** with the contents of [`open-webui/functions/run_code.py`](https://raw.githubusercontent.com/EtiennePerot/safe-code-execution/master/open-webui/functions/run_code.py).
* Click the `Save` button.
* Activate both toggles on the function you just created.

<details>
<summary>See screenshot</summary>
<div align="center">
	<p>
		<img src="https://github.com/EtiennePerot/safe-code-execution/blob/master/res/functions.png?raw=true" alt="Functions list"/>
	</p>
</div>
</details>

### Function: How to use

Ask the model to generate code, then click the `Run code` button under the message to run it.

<details>
<summary>See screenshot</summary>
<div align="center">
	<p>
		<img src="https://github.com/EtiennePerot/safe-code-execution/blob/master/res/code-execution-function.gif?raw=true" alt="Code execution tool"/>
	</p>
	<p>
		<em>Code execution function used to inform the model of the current date, along with demo of gVisor sandboxing and internet reachability.</em>
	</p>
</div>
</details>

## Code execution tool

The **code execution tool** grants the LLM the ability to run code by itself. This is similar to granting "Web search" access which lets the LLM search the Web by itself. If the LLM decides to use this tool, the tool's output is invisible to you but is available as information for the LLM.

### Tool: How to install

First, [**set up Open WebUI for sandboxing**](docs/setup.md).

Then, in Open WebUI:

* Go to `Workspace` → `Tools`.
* Click the `+`.
* Input the following:
    * **Toolkit name**: `Run code`
    * **Toolkit description**: `Run arbitrary code safely in a gVisor sandbox.`
    * Replace the **code section** with the contents of [`open-webui/tools/run_code.py`](https://raw.githubusercontent.com/EtiennePerot/safe-code-execution/master/open-webui/tools/run_code.py).
* Click the `Save` button.

<details>
<summary>See screenshot</summary>
<div align="center">
	<p>
		<img src="https://github.com/EtiennePerot/safe-code-execution/blob/master/res/tools.png?raw=true" alt="Tools list"/>
	</p>
</div>
</details>

### Tool: How to enable for a model

The tool needs to be enabled on a per-model basis.

* Go to `Workspace` → `Models`.
* Click the pencil (✏️) icon on a model that supports [tool calling](https://ollama.com/blog/tool-support).
* Under `Tools`, check the `Run Code` checkbox.
* Click `Save & Update`.

<details>
<summary>See screenshot</summary>
<div align="center">
	<p>
		<img src="https://github.com/EtiennePerot/safe-code-execution/blob/master/res/model.png?raw=true" alt="Models list"/>
	</p>
</div>
</details>

### Tool: How to use

When prompting the model, activate the "Run code" toggle on the message box. Then write your prompt.

<details>
<summary>See screenshot</summary>
<div align="center">
	<p>
		<img src="https://github.com/EtiennePerot/safe-code-execution/blob/master/res/code-execution-tool.gif?raw=true" alt="Code execution tool"/>
	</p>
	<p>
		<em>Code execution tool looking up the date, retrieving a webpage that was not in its training set, and performing complex computations.</em>
	</p>
</div>
</details>
