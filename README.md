# Code execution for Open WebUI

Safe code execution capabilities for [Open WebUI](https://openwebui.com/). Uses [gVisor](https://gvisor.dev) for safe sandboxing.

## Function? Tool? Which one do I want?

Open WebUI addons come in multiple types. For code execution, this repository contains both a **code execution function** and a **code execution tool**.

| **Code execution function** | **Code execution tool** |
| --------------------------- | ----------------------- |
| ![Code execution function](https://github.com/EtiennePerot/open-webui-code-execution/blob/master/res/code-execution-function.gif?raw=true) | ![Code execution tool](https://github.com/EtiennePerot/open-webui-code-execution/blob/master/res/code-execution-tool.gif?raw=true) |

* The **code execution function** shows up as a button under LLM-generated messages. When you click it, the code in the code block of this message will execute. The output is shown in the UI, and is also available to the LLM for further querying.
* The **code execution tool** grants the LLM the ability to run code by itself. This is similar to granting "Web search" access which lets the LLM search the Web by itself. If the LLM decides to use this tool, the tool's output is invisible to you but is available as information for the LLM.

You can install both.

## Code execution function

### How to install

In Open WebUI:

* Go to `Workspace` → `Functions`.
* Click the `+`.
* Input the following:
    * **Function name**: `Run code`
    * **Function description**: `Run arbitrary code safely in a gVisor sandbox.`
    * Replace the **code section** with the contents of [`open-webui/functions/run_code.py`](https://raw.githubusercontent.com/EtiennePerot/open-webui-code-execution/master/open-webui/functions/run_code.py).
* Click the `Save` button.
* Activate both toggles on the function you just created.

<div align="center">
	<p>
		<img src="https://github.com/EtiennePerot/open-webui-code-execution/blob/master/res/functions.png?raw=true" alt="Models list"/>
	</p>
</div>

### How to use

Ask the model to generate code, then click the `Run code` button under the message to run it.

<div align="center">
	<p>
		<img src="https://github.com/EtiennePerot/open-webui-code-execution/blob/master/res/code-execution-function.gif?raw=true" alt="Code execution tool"/>
	</p>
	<p>
		<em>Code execution function used to inform the model of the current date, along with demo of gVisor sandboxing and internet reachability.</em>
	</p>
</div>

## Code execution tool

### How to install

In Open WebUI:

* Go to `Workspace` → `Tools`.
* Click the `+`.
* Input the following:
    * **Toolkit name**: `Run code`
    * **Toolkit description**: `Run arbitrary code safely in a gVisor sandbox.`
    * Replace the **code section** with the contents of [`open-webui/tools/run_code.py`](https://raw.githubusercontent.com/EtiennePerot/open-webui-code-execution/master/open-webui/tools/run_code.py).
* Click the `Save` button.

<div align="center">
	<p>
		<img src="https://github.com/EtiennePerot/open-webui-code-execution/blob/master/res/tools.png?raw=true" alt="Tools list"/>
	</p>
</div>

### How to enable for a model

* Go to `Workspace` → `Models`.
* Click the pencil (✏️) icon on a model that supports tool calling.
* Under `Tools`, check the `Run Code` checkbox.
* Click `Save & Update`.

<div align="center">
	<p>
		<img src="https://github.com/EtiennePerot/open-webui-code-execution/blob/master/res/models.png?raw=true" alt="Models list"/>
	</p>
</div>

### How to use

When prompting the model, activate the "Run code" toggle on the message box. Then write your prompt.

<div align="center">
	<p>
		<img src="https://github.com/EtiennePerot/open-webui-code-execution/blob/master/res/code-execution-tool.gif?raw=true" alt="Code execution tool"/>
	</p>
	<p>
		<em>Code execution tool looking up the date, retrieving a webpage that was not in its training set, and performing complex computations.</em>
	</p>
</div>
