# Open WebUI setup

Both the code execution function and tool require the ability to run [gVisor](https://gvisor.dev) for secure sandboxing. Your Open WebUI instance needs to be set up to handle this.

## Supported environment

This utility should work wherever gVisor works, i.e. x86_64/AMD64 and ARM64 processors.

gVisor only runs on Linux. However, if you are running on Windows or OS X, you can use [Docker Desktop](https://www.docker.com/products/docker-desktop/) or similar container runtime which will automatically run a Linux virtual machine in which the container will actually run.

## Container runtime setup

If you run Open WebUI inside a container, you will need to adjust its settings to grant gVisor the necessary privileges to work. The code contains self-checks which will let you know if your setup needs work, but in general you will at minimum need to do the following:

### The easy way: Run in `--privileged` mode

Adding `--privileged=true` to `docker run` will remove all of Docker's security measures. This offers a similar profile as if you were running Open WebUI as root without a container. Code running as part of the code execution function/tool will still run in a gVisor sandbox. If this sounds OK for your needs (for example if this is a single-user instance and you trust Open WebUI's code), this is a quick way to get set up. Otherwise, read on for the hard way.

### The hard way

* Remove the default **system call filter**:
    * **Why**: This is necessary so that gVisor can create isolated namespaces via the [unshare(2) system call](https://www.man7.org/linux/man-pages/man2/unshare.2.html).
    * On **Docker**: Add `--security-opt=seccomp=unconfined` to `docker run`.
    * On **Kubernetes**: Set [`spec.securityContext.seccompProfile.type`](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-seccomp-profile-for-a-container) to `Unconfined`.
* If you have **SELinux** enabled, set the `container_engine_t` label:
    * **Why**: The default SELinux label for containers (`container_t`) does not allow the creation of namespaces, which gVisor requires for isolation. The `container_engine_t` label allows this.
    * On **Docker**: Add `--security-opt=label=type:container_engine_t` to `docker run`.
    * On **Kubernetes**: Set [`spec.securityContext.seLinuxOptions.type`](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#assign-selinux-labels-to-a-container) to `container_engine_t`.
* If you want to use resource limiting, **mount `cgroupfs` as read-write**
    * **Why**: This is necessary so that gVisor can create child cgroups with memory usage limits.
    * On **Docker**: Add `--mount=type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup,readonly=false` to `docker run`.
    * On **Kubernetes**: Add a [`hostPath` volume](https://kubernetes.io/docs/concepts/storage/volumes/#hostpath) with `path` set to `/sys/fs/cgroup`, then mount it in your container's `volumeMounts` with options `mountPath` set to `/sys/fs/cgroup` and `readOnly` set to `false`.

## Self-test mode

To verify that your setup works, you can run the tool in self-test mode using `run_code.py`'s `--use-sample-code` flag.

For example, here is a Docker invocation running the `run_code.py` script inside the Open WebUI container image with the above flags:

```shell
$ git clone https://github.com/EtiennePerot/open-webui-code-execution && \
  docker run --rm \
    --security-opt=seccomp=unconfined \
    --security-opt=label=type:container_engine_t \
    --mount=type=bind,source="$(pwd)/open-webui-code-execution",target=/selftest \
    ghcr.io/open-webui/open-webui:main \
    python3 /selftest/open-webui/tools/run_code.py --use-sample-code
```

If all goes well, you should see:

```
Event: {'type': 'status', 'data': {'status': 'in_progress', 'description': 'Checking if environment supports sandboxing...', 'done': False}}
Event: {'type': 'status', 'data': {'status': 'in_progress', 'description': 'Auto-installing gVisor...', 'done': False}}
Event: {'type': 'status', 'data': {'status': 'in_progress', 'description': 'Initializing sandbox configuration...', 'done': False}}
Event: {'type': 'status', 'data': {'status': 'in_progress', 'description': 'Setting up sandbox environment...', 'done': False}}
Event: {'type': 'status', 'data': {'status': 'in_progress', 'description': 'Running Python code in gVisor sandbox...', 'done': False}}
Event: {'type': 'status', 'data': {'status': 'complete', 'description': 'Python code executed successfully.', 'done': True}}
{"status": "OK", "output": "Hello from the sandbox!\nCurrent date and time: 2024-09-04 05:06:26.021759\n[    0.000000] Starting gVisor... [...]"}
```

If you get an error, try to add the `--debug` flag at the very end of this command (i.e. as a `run_code.py` flag) for extra information, then file a bug.

## Set valves

The code execution tool and function have the following valves available:

* **Networking allowed**: Whether or not to let sandboxed code have access to the network.
  * **Note**: If you are running Open WebUI on a LAN, this will expose your LAN.
* **Max runtime**: The maximum number of time (in seconds) that sandboxed code will be allowed to run.
  * Useful for multi-user setups to avoid denial-of-service, and to avoid running LLM-generated code that contains infinite loops forever.
* **Max RAM**: The maximum amount of memory the sandboxed code will be allowed to use, in megabytes.
  * Useful for multi-user setups to avoid denial-of-service.
  * RAM limiting requires `cgroupfs` to be mounted as read-write. See above for how to do this.
* **Auto Install**: Whether to automatically download and install gVisor if not present in the container.
  * If not installed, gVisor will be automatically installed in `/tmp`.
  * Useful for convenience, but should be disabled for production setups.

## Optional: Pre-install gVisor

To avoid the tool having to download and install gVisor on first run, you can pre-install gVisor in your Open WebUI container image or environment. Follow the [gVisor installation guide](https://gvisor.dev/docs/user_guide/install/). At the end, the command `runsc --version` (run within the Open WebUI container if you are running it in a container) should work and return the gVisor version you installed.

## Optional: Lockdown for production setups

TODO: Add environment variables that take precedence over valves to allow multi-user setups.
