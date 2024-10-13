# Open WebUI setup

Both the code execution function and tool require the ability to run [gVisor](https://gvisor.dev) for secure sandboxing.

Your Open WebUI instance needs to be set up to handle this.

## Supported environment

This utility should work wherever gVisor works, i.e. x86_64/AMD64 and ARM64 processors.

gVisor only runs on Linux. However, if you are running on Windows or OS X, you can use [Docker Desktop](https://www.docker.com/products/docker-desktop/) or similar container runtime; this will automatically run a Linux virtual machine in which the container will actually run.

## Container runtime setup

If you run Open WebUI inside a container, you will need to adjust its settings to grant gVisor the necessary privileges to work.

You can do this the **easy way** (good for single-user setups) by running Open WebUI in privileged mode, or the **hard way** to change the minimal set of things that still allows sandboxing to be possible.

### The easy way: Run Open WebUI in privileged mode

<details>
<summary>If you are running Open WebUI on your own computer, without exposing it to the Internet, and you trust Open WebUI's code, click this section. Otherwise, click "the hard way" below.</summary>
<br/>

* On **Docker**: Add `--privileged=true` to `docker run`.
* On **Kubernetes**: Set `spec.securityContext.privileged` to `true`.

**This will remove all security measures** from the Open WebUI container. From a security perspective, this is roughly equivalent to running the Open WebUI server as root outside of a container on the host machine. However, **code running as part of this code execution function/tool will still run in a secure gVisor sandbox** and cannot impact the host or the Open WebUI container.

This is adequate for single-user setups not exposed to the outside Internet, while still providing strong security against LLMs generating malicious code. However, if you are running a multi-user setup, or if you do not fully trust Open WebUI's code, or the Open WebUI server's HTTP port is exposed to the outside Internet, you may want to harden it further. If so, **don't** set the `privileged` setting, and read on to "the hard way" instead.

</details>

### The hard way

<details>
<summary>Click to expand this section describing the minimal subset of changes that <code>--privileged=true</code> does that is still necessary for sandboxing to work.</summary>
<br/>

* Remove the container's default **system call filter** (`seccomp`):
    * On **Docker**: Add `--security-opt=seccomp=unconfined` to `docker run`.
    * On **Kubernetes**: Set [`spec.securityContext.seccompProfile.type`](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-seccomp-profile-for-a-container) to `Unconfined`.
    * If you would like to use a specific seccomp profile rather than running without system call filtering, you can use [Dangerzone's seccomp profile](https://github.com/freedomofpress/dangerzone/blob/main/share/seccomp.gvisor.json) which is tuned to allow gVisor system calls through.
    * **Why**: By default, some system calls are blocked by the [container runtime's default system call filter](https://docs.docker.com/engine/security/seccomp/#significant-syscalls-blocked-by-the-default-profile). The use of these system calls **enhances security when running subcontainers**, but they are blocked by default because most containerized applications don't ever *need* to create subcontainers. gVisor, however, does. Specifically, gVisor needs to:
        * ... create isolated namespaces using the [`unshare(2)` system call](https://www.man7.org/linux/man-pages/man2/unshare.2.html)
        * ... create isolated chroots via the [`mount(2)` system call](https://www.man7.org/linux/man-pages/man2/mount.2.html)
        * ... `pivot_root` into these roots via the [`pivot_root(2)` system call](https://www.man7.org/linux/man-pages/man2/pivot_root.2.html)
        * ... trace sandboxed processes to block their system calls from reaching the host Linux kernel using the [`ptrace(2)` system call](https://www.man7.org/linux/man-pages/man2/ptrace.2.html)
* **Mount `cgroupfs` as writable**:
    * On **Docker**: Add `--mount=type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup,readonly=false` to `docker run`.
    * On **Kubernetes**: Add a [`hostPath` volume](https://kubernetes.io/docs/concepts/storage/volumes/#hostpath) with `path` set to `/sys/fs/cgroup`, then mount it in your container's `volumeMounts` with options `mountPath` set to `/sys/fs/cgroup` and `readOnly` set to `false`.
    * **Why**: This is needed so that gVisor can create child [cgroups](https://en.wikipedia.org/wiki/Cgroups), necessary to enforce per-sandbox resource usage limits.
    * If you wish to disable resource limiting on code evaluation sandboxes, you can skip this setting and not mount `cgroupfs` at all in the container. Note that this means code evaluation sandboxes will be able to take as much CPU and memory as they want.
* **Mount `procfs` at `/proc2`**:
    * On **Docker**: Add `--mount=type=bind,source=/proc,target=/proc2,readonly=false,bind-recursive=disabled` to `docker run`.
    * On **Kubernetes**: Add a [`hostPath` volume](https://kubernetes.io/docs/concepts/storage/volumes/#hostpath) with `path` set to `/proc`, then mount it in your container's `volumeMounts` with options `mountPath` set to `/proc2` and `readOnly` set to `false`.
    * **Why**: By default, in non-privileged mode, the container runtime will mask certain sub-paths of `/proc` inside the container by creating submounts of `/proc` (e.g. `/proc/bus`, `/proc/sys`, etc.). gVisor does not really care or use anything under these sub-mounts, but *does* need to be able to mount `procfs` in the chroot environment it isolates itself in. However, its ability to mount `procfs` requires having an existing unobstructed view of `procfs` (i.e. a mount of `procfs` with no submounts). Otherwise, such mount attempts will be denied by the kernel (see the explanation for "locked" mounts on [`mount_namespaces(7)`](https://www.man7.org/linux/man-pages/man7/mount_namespaces.7.html)). Therefore, exposing an unobstructed (non-recursive) view of `/proc` elsewhere in the container filesystem (such as `/proc2`) informs the kernel that it is OK for this container to be able to mount `procfs`.
* Remove the container's default **AppArmor profile**:
    * On **Docker**: Add `--security-opt=apparmor=unconfined` to `docker run`.
    * On **Kubernetes**: Set [`spec.securityContext.appArmorProfile.type`](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-apparmor-profile-for-a-container) to `Unconfined`.
    * **Why**: By default, the capability to `mount` filesystems are blocked by the [container runtime's default AppArmor profile](https://github.com/moby/moby/blob/96ea6e0f9bed4b6936f4b266b207100812aec0b7/profiles/apparmor/template.go#L45). In order to sandbox itself, gVisor uses [`pivot_root(2)`](https://www.man7.org/linux/man-pages/man2/pivot_root.2.html)s to restrict its own view of the filesystem. For this to work, it needs a minimal set of mounted filesystems to exist in that view, hence needing to `mount` them there.
* **Set the `container_engine_t` SELinux label**:
    * On **Docker**: Add `--security-opt=label=type:container_engine_t` to `docker run`.
    * On **Kubernetes**: Set [`spec.securityContext.seLinuxOptions.type`](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#assign-selinux-labels-to-a-container) to `container_engine_t`.
    * **Why**: The default SELinux label for containers (`container_t`) does not allow the creation of namespaces, which gVisor requires for additional isolation . The `container_engine_t` label allows this.
    * If you don't have SELinux enabled, this setting does nothing and may be omitted.

#### Does the "hard way" actually provide more security than privileged mode?

**The short answer**: Yes; a container running in privileged mode basically has full access to the host, whereas the subset of security options listed in the "hard way" still provide isolation.

<details>
<summary>Expand this section for the longer answer.</summary>
<br/>

**The long answer**: The most important security aspect that the above setting **do not modify** but that privileged mode does is the set of **[Linux capabilities](https://www.man7.org/linux/man-pages/man7/capabilities.7.html)** granted to the process running in the Open WebUI container. In privileged mode, the container is granted, for example:

* `CAP_NET_ADMIN`, which allows it to reconfigure the kernel's network stack.
* `CAP_SYS_ADMIN`, which allows it to escape the container and run any process on the host.
* `CAP_SYS_MODULE`, which allows it to install any kernel module.

You can check this using the `capsh` binary:

```shell
# Without privileged mode:
$ docker run --rm ghcr.io/open-webui/open-webui:main sh -c 'apt-get update; apt-get install -y libcap2-bin; capsh --print' | grep 'Bounding set'
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap

# With privileged mode:
$ docker run --rm --privileged=true ghcr.io/open-webui/open-webui:main sh -c 'apt-get update; apt-get install -y libcap2-bin; capsh --print' | grep 'Bounding set'
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore
```

To illustrate the difference, here's how an Open WebUI running in privileged mode can get full write access to the host's root filesystem. This will not work in non-privileged mode.

```shell
$ docker run --rm -it --privileged=true ghcr.io/open-webui/open-webui:main bash

# List the host's block storage devices.
root@container:/app/backend# lsblk
NAME   MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS
sda      8:0    0 111.8G  0 disk
├─sda1   8:1    0  63.4G  0 part
├─sda2   8:2    0   507M  0 part
├─sda3   8:3    0   128M  0 part
[...]

# Mount the root block device at `/mnt`.
root@container:/app/backend# mount /dev/sda1 /mnt

# Full access to the host's root filesystem.
root@container:/app/backend# tree -L 2 /mnt
/mnt
├── bin -> usr/bin
├── boot
├── dev
├── etc
│   ├── apparmor
│   ├── apparmor.d
│   ├── bash.bashrc
│   ├── crontab
│   ├── [...]
│   ├── modprobe.d
│   ├── modules-load.d
│   ├── passwd
│   ├── profile
│   ├── profile.d
│   ├── rc.d
│   ├── shadow
│   ├── sudoers
│   ├── sudoers.d
│   ├── [...]
│   └── zsh
├── home
│   ├── [...]
│   └── [YOUR_NAME_HERE]
├── lib -> usr/lib
├── lib64 -> usr/lib
├── lost+found
├── media
│   ├── [...]
│   └── autofs
├── mnt
├── opt
│   └── [...]
├── proc
├── root
├── run
├── sbin -> usr/bin
├── srv
│   ├── ftp
│   └── http
├── sys
├── tmp
├── usr
│   ├── bin
│   ├── lib
│   └── [...]
└── var
    ├── [...]
    └── tmp
```

While this document will not elaborate on how, it should be fairly obvious how one can escalate to full root access on the host from there.

</details>
</details>

## **Optional** setup

### **Optional**: Configuration: Set valves

<details>
<summary>The code execution tool and function can be configured using valves.</summary>
<br/>

* **Networking allowed**: Whether or not to let sandboxed code have access to the network.
  * **Note**: If you are running Open WebUI on a LAN, this will expose your LAN.
* **Max runtime**: The maximum number of time (in seconds) that sandboxed code will be allowed to run.
  * Useful for multi-user setups to avoid denial-of-service, and to avoid running LLM-generated code that contains infinite loops forever.
* **Max RAM**: The maximum amount of memory the sandboxed code will be allowed to use, in megabytes.
  * Useful for multi-user setups to avoid denial-of-service.
* **Resource limiting enforcement**: Whether to enforce that code evaluation sandboxes are resource-limited.
  * This is enabled by default, and requires cgroups v2 to be present on your system and mounted in the Open WebUI container.
  * If you do not mind your code evaluation sandboxes being able to use as much CPU and memory as they want, you may disable this setting (set it to `false`).
  * On systems that only have cgroups v1 and not cgroups v2, such as WSL and some old Linux distributions, you may need to disable this.
* **Auto install**: Whether to automatically download and install gVisor if not present in the container.
  * If not installed, gVisor will be automatically installed in `/tmp`.
  * You can set the HTTPS proxy used for this download using the `HTTPS_PROXY` environment variable.
  * Useful for convenience, but should be disabled for production setups. See below on how to pre-install gVisor.
* **Check for updates**: Whether to automatically check for updates.
  * When enabled, update checking will happen at most once every three days.
  * You can set the HTTPS proxy used for this download using the `HTTPS_PROXY` environment variable.
* **Debug**: Whether to produce debug logs.
  * This should never be enabled in production setups as it produces a lot of information that isn't necessary for regular use.
  * **When filing a bug report**, please enable this valve, then reproduce the issue in a new chat session, then download the chat log (triple-dot menu → `Download` → `Export chat (.json)`) and attach it to the bug report.

</details>

### **Optional**: Run self-tests

<details>
<summary>To verify that your setup works, you can run the function and the tool in self-test mode using the <code>--self_test</code> flag.</summary>
<br/>

For example, here is a Docker invocation running the `run_code.py` script inside the Open WebUI container image with the above flags:

```shell
$ git clone https://github.com/EtiennePerot/safe-code-execution && \
  cd safe-code-execution && \
  docker run --rm \
    --security-opt=seccomp=unconfined \
    --security-opt=apparmor=unconfined \
    --security-opt=label=type:container_engine_t \
    --mount=type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup,readonly=false \
    --mount=type=bind,source=/proc,target=/proc2,readonly=false,bind-recursive=disabled \
    --mount=type=bind,source="$(pwd)",target=/test \
    ghcr.io/open-webui/open-webui:main \
    sh -c 'python3 /test/open-webui/tools/run_code.py --self_test && python3 /test/open-webui/functions/run_code.py --self_test'
```

If all goes well, you should see:

```
⏳ Running self-test: simple_python
✔ Self-test simple_python passed.
⏳ Running self-test: simple_bash
✔ Self-test simple_bash passed.
⏳ Running self-test: bad_syntax_python
✔ Self-test bad_syntax_python passed.
⏳ Running self-test: bad_syntax_bash
✔ Self-test bad_syntax_bash passed.
⏳ Running self-test: long_running_code
✔ Self-test long_running_code passed.
⏳ Running self-test: ram_hog
✔ Self-test ram_hog passed.
✅ All tool self-tests passed, good go to!
...
✅ All function self-tests passed, good go to!
```

If you get an error, try to add the `--debug` to each `run_code.py` invocation for extra information, then file a bug.

</details>

### **Optional**: Pre-install gVisor

<details>
<summary>To avoid the tool having to download and install gVisor on first run, you can <strong>optionally</strong> pre-install gVisor in your Open WebUI container image or environment.</summary>
<br/>

For example, here is a sample `Dockerfile` that extends the Open WebUI container image and pre-installs gVisor:

```Dockerfile
# Note: Using this Dockerfile is optional.
FROM ghcr.io/open-webui/open-webui:main

# Install `wget`.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y </dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y wget </dev/null

# Install gVisor at `/usr/bin/runsc`.
RUN wget -O /tmp/runsc "https://storage.googleapis.com/gvisor/releases/release/latest/$(uname -m)/runsc" && \
    wget -O /tmp/runsc.sha512 "https://storage.googleapis.com/gvisor/releases/release/latest/$(uname -m)/runsc.sha512" && \
    cd /tmp && sha512sum -c runsc.sha512 && \
    chmod 555 /tmp/runsc && rm /tmp/runsc.sha512 && mv /tmp/runsc /usr/bin/runsc
```

</details>

### **Optional**: Add packages to Open WebUI `Dockerfile`

<details>
<summary>To allow code execution sandboxes to use tools or Python packages that aren't part of the Open WebUI container image, you can preinstall them in the `Dockerfile`.</summary>
<br/>

For example, here is a sample `Dockerfile` that extends the Open WebUI container image and installs the `sudo` and `ping` tools along with some Python packages:

```Dockerfile
FROM ghcr.io/open-webui/open-webui:main

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y </dev/null && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      iputils-ping sudo \
    </dev/null && \
    pip install matplotlib yfinance numpy
```

</details>

### **Optional**: Lockdown for production setups

<details>
<summary>All valves can be overridden using environment variables. Doing so will take precedence over the settings in Open WebUI.</summary>
<br/>

You may override any valve using environment variables prefixed by `CODE_EVAL_VALVE_OVERRIDE_`. This is recommended for production setups, because this can be done at container definition time and does not depend on Open WebUI's stateful configuration. It is also more straightforward to reason about. Additionally, the default valve settings are set to maximize ease of installation for single-user setups, but are **not suitable for production multi-user setups**.

Using code evaluation in a production multi-user setup requires taking all security precautions. The first such precaution is to **configure Open WebUI for sandboxing using "the hard way"** described above. Running Open WebUI in privileged mode is risky.

Once you have done this, consider setting the following environment variable:

* `CODE_EVAL_VALVE_OVERRIDE_MAX_RUNTIME_SECONDS`: The maximum number of seconds that each sandbox is allowed to run for. **This should be non-zero**.
* `CODE_EVAL_VALVE_OVERRIDE_MAX_RAM_MEGABYTES`: The maximum amount of memory (in megabytes) that each sandbox is allowed to use. **This should be non-zero**.
* `CODE_EVAL_VALVE_OVERRIDE_AUTO_INSTALL`: **This should be set to `false`** to disable automatic installation of gVisor. **You should preinstall gVisor** instead, as described in an earlier section.
* `CODE_EVAL_VALVE_OVERRIDE_DEBUG`: **This should be set to `false`**. Debug information reveals a lot of system information that you do not want to expose to users.
* `CODE_EVAL_VALVE_OVERRIDE_MAX_FILES_PER_EXECUTION`: The maximum number of newly-created files to retain in each sandbox execution. **This should be non-zero**.
* `CODE_EVAL_VALVE_OVERRIDE_MAX_FILES_PER_USER`: The maximum number of files that can be stored long-term for a single user. **This should be non-zero**.
* `CODE_EVAL_VALVE_OVERRIDE_MAX_MEGABYTES_PER_USER`: The maximum amount of total long-term file storage (in megabytes) that each user may use. **This should be non-zero**.
* `CODE_EVAL_VALVE_OVERRIDE_REQUIRE_RESOURCE_LIMITING`: Whether to require that code evaluation sandboxes are resource-limited. **This should be set to `true`**.
* `CODE_EVAL_VALVE_OVERRIDE_WEB_ACCESSIBLE_DIRECTORY_PATH`: The directory where user files are stored. **This should be overridden** to prevent it from being modified by users to reveal or overwrite sensitive files in the Open WebUI installation.
* `CODE_EVAL_VALVE_OVERRIDE_WEB_ACCESSIBLE_DIRECTORY_URL`: The HTTP URL of the directory specified by `CODE_EVAL_VALVE_OVERRIDE_WEB_ACCESSIBLE_DIRECTORY_PATH`. This can start with a `/` to make it domain-relative. **This should be overridden** to prevent users from modifying it in such a way that it tricks other users into clicking unrelated links.
* `CODE_EVAL_VALVE_OVERRIDE_NETWORKING_ALLOWED`: **This should be set to `false`** if running on a LAN with sensitive services that sandboxes could reach out to. Firewall rules are not yet supported, so this setting is currently all-or-nothing.

</details>
