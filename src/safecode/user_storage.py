import base64
import fcntl
import hashlib
import mimetypes
import os
import os.path
import shutil
import stat
import time
import typing
import urllib.parse
import uuid


class UserStorage:
    class StorageException(Exception):
        """Base class for storage-related exceptions."""

    class OutOfStorageException(Exception):
        """Not enough files or bytes quota."""

    class EnvironmentNeedsSetupException(Exception):
        """Storage is badly configured."""

    # Number of zeroes to use in nonces (in per-day storage directories).
    # This effectively limits the number of nonces usable in a given day.
    NUM_NONCE_ZEROS = 4

    # Free space buffer to keep free on the underlying storage device,
    # rather than allowing user storage to fill it to the brim.
    MUST_KEEP_FREE_MARGIN_MEGABYTES = 512

    class File:
        MAX_INLINE_URL_SIZE = 0
        MAX_INLINE_TEXT_LINES = 128
        MAX_INLINE_TEXT_BYTES = 65535

        def __init__(self, file_path, file_relative_path, file_url, file_size):
            self._file_path = file_path
            self._file_relative_path = file_relative_path
            self._file_url = file_url
            self._size_bytes = file_size
            mimetypes.init()
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type is None:
                mime_type, _ = mimetypes.guess_type(file_url)
            if mime_type is None:
                # Check if the file is valid UTF-8 text.
                is_utf8 = True
                is_empty = True
                with open(self._file_path, "rb") as f:
                    for line in f:
                        is_empty = is_empty or len(line) > 0
                        try:
                            line.decode("utf-8")
                        except UnicodeDecodeError:
                            is_utf8 = False
                mime_type = (
                    "text/plain"
                    if (is_utf8 and not is_empty)
                    else "application/octet-stream"
                )
            self._mime_type = mime_type
            self._cached_markdown = None

        @property
        def name(self):
            return self._file_relative_path

        @property
        def url(self):
            if self._size_bytes > 0 and self._size_bytes <= self.MAX_INLINE_URL_SIZE:
                # Try to use an inline URL.
                with open(self._file_path, "rb") as f:
                    contents = f.read()
                inline_url = f"data:{self._mime_type}," + urllib.parse.quote_from_bytes(
                    contents
                )
                inline_base64 = (
                    f"data:{self._mime_type};base64,"
                    + base64.standard_b64encode(contents).decode("ascii")
                )
                shortest_url = (
                    inline_url
                    if len(inline_url) < len(inline_base64)
                    else inline_base64
                )
                if len(shortest_url) <= self.MAX_INLINE_URL_SIZE:
                    return shortest_url
            return self._file_url

        def _inline_markdown(self):
            """Render the file as inline text or markdown if small enough; otherwise return None."""
            if self._size_bytes > self.MAX_INLINE_TEXT_BYTES:
                return None
            if self._mime_type.startswith("image/"):
                return f"\U0001f5bc [{self.name}]({self.url}):  \n![{self.name}]({self.url})"
            if not self._mime_type.startswith("text/"):
                return None
            with open(self._file_path, "rb") as f:
                try:
                    contents = f.read().decode("utf-8")
                except UnicodeDecodeError:
                    return None
            lines = contents.split("\n")
            if len(lines) > self.MAX_INLINE_TEXT_LINES:
                return None
            if self._mime_type != "text/markdown":
                if "```" in contents:
                    return None
                if contents and contents[-1] == "\n":
                    contents = contents[:-1]
                return f"\U0001f4c4 [{self.name}]({self.url}):\n```\n{contents}\n```"
            components = [f"\U0001f4c3 [{self.name}]({self.url}):"]
            for line in lines:
                components.append(f"> {line}")
            if components[-1] == "> ":
                components = components[:-1]
            return "\n".join(components)

        def _markdown(self):
            if self._size_bytes == 0:
                return f"\u2049 `{self.name}` (empty)"
            inline_markdown = self._inline_markdown()
            if inline_markdown is not None:
                return inline_markdown
            icon = "\U0001f4be"
            if self._mime_type.startswith("text/"):
                icon = "\U0001f4c4"
            elif self._mime_type.startswith("image/"):
                icon = "\U0001f5bc"
            elif self._mime_type.startswith("audio/"):
                icon = "\U0001f3b5"
            elif self._mime_type.startswith("video/"):
                icon = "\U0001f3ac"
            size = f"{self._size_bytes} bytes"
            if self._size_bytes > 1024 * 1024 * 1024:
                size = f"{self._size_bytes // 1024 // 1024 // 1024} GiB"
            elif self._size_bytes > 1024 * 1024:
                size = f"{self._size_bytes // 1024 // 1024} MiB"
            elif self._size_bytes > 1024:
                size = f"{self._size_bytes // 1024} KiB"
            return f"{icon} [{self.name}]({self.url}) ({size})"

        def markdown(self):
            if self._cached_markdown is None:
                self._cached_markdown = self._markdown()
            return self._cached_markdown

    @classmethod
    def measure_directory(cls, path, predicate=None):
        """
        Measure storage cost of a directory.

        :param path: Path to the directory to measure.
        :param predicate: Optional predicate to filter files and directories, called with absolute paths.
        :return: 2-tuple `(total_files, total_bytes)`. Note that `total_files` counts the number of non-root directories as well, and `total_bytes` also includes storage necessary to store filenames and directory names.
        """
        path = os.path.normpath(os.path.abspath(path))
        total_files = 0
        total_bytes = 0
        try:
            for dirpath, subdirs, subfiles in os.walk(
                path, onerror=None, followlinks=False
            ):
                dirpath = os.path.normpath(os.path.abspath(dirpath))
                for subdir in subdirs:
                    if predicate is None or predicate(os.path.join(dirpath, subdir)):
                        total_files += 1
                        total_bytes += len(subdir)
                for subfile in subfiles:
                    subfile_path = os.path.join(dirpath, subfile)
                    if predicate is not None and not predicate(subfile_path):
                        continue
                    try:
                        subfile_stat = os.stat(subfile_path, follow_symlinks=False)
                    except FileNotFoundError:
                        continue  # Likely raced with another execution.
                    if not stat.S_ISREG(subfile_stat.st_mode):
                        continue  # Ignore non-regular files.
                    total_files += 1
                    total_bytes += len(subfile)
                    total_bytes += subfile_stat.st_size
        except OSError as e:
            raise cls.EnvironmentNeedsSetupException(
                f"Failed to explore directory {path} (please adjust permissions): {e}"
            )
        return total_files, total_bytes

    def __init__(
        self,
        storage_root_path,
        storage_root_url,
        __user__: typing.Optional[dict] = None,
        max_files_per_user=None,
        max_bytes_per_user=None,
    ):
        if storage_root_path.startswith("$DATA_DIR" + os.sep):
            if "DATA_DIR" not in os.environ:
                data_dir = "/app/backend/data"
                if not os.path.isdir(data_dir):
                    if os.path.isdir("/app/backend"):
                        os.makedirs(data_dir, mode=0o755)
                    else:
                        raise self.EnvironmentNeedsSetupException(
                            f"DATA_DIR specified in user storage configuration ({storage_root_path}), but not specified in environment, and default path '/app/backend/data' does not exist; please create it or configure user storage directory."
                        )
            else:
                data_dir = os.environ["DATA_DIR"]
            storage_root_path = os.path.join(
                data_dir,
                storage_root_path[len("$DATA_DIR" + os.sep) :].lstrip(os.sep),
            )
        self._storage_root_path = os.path.normpath(os.path.abspath(storage_root_path))
        try:
            os.makedirs(self._storage_root_path, mode=0o755, exist_ok=True)
        except OSError as e:
            raise self.EnvironmentNeedsSetupException(
                f"User storage directory ({self._storage_root_path}) does not exist and cannot automatically create it ({e}); please create it or reconfigure it."
            )
        self._storage_root_url = storage_root_url.rstrip("/")
        self._date = time.strftime("%Y/%m/%d")
        self._max_files_per_user = max_files_per_user
        self._max_bytes_per_user = max_bytes_per_user
        self._user = f"anon_{self._date}"
        if __user__ is not None:
            if type(__user__) is type({}):
                self._user = str(
                    "|".join(
                        f"{k}={v}"
                        for k, v in sorted(__user__.items(), key=lambda x: x[0])
                    )
                )
            else:
                self._user = str(__user__)
        user_hash = hashlib.sha512()
        user_hash.update(self._user.encode("utf-8"))
        self._user_hash = (
            base64.b32encode(user_hash.digest()).decode("ascii").lower()[:12]
        )
        self._user_path = os.path.join(storage_root_path, self._user_hash)
        self._lock_fd = None

    def __enter__(self):
        assert self._lock_fd is None
        os.makedirs(self._user_path, mode=0o755, exist_ok=True)
        lock_fd = os.open(
            os.path.join(self._user_path, ".lock"),
            os.O_RDWR | os.O_CREAT | os.O_TRUNC,
        )
        deadline = time.time() + 10
        last_exception = None
        while time.time() < deadline:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (IOError, OSError) as e:
                last_exception = e
                time.sleep(0.01)
            else:
                self._lock_fd = lock_fd
                break
        if self._lock_fd is None:
            os.close(lock_fd)
            raise self.StorageException(
                f"Cannot lock storage directory (too many concurrent code executions?) {last_exception}"
            )

    def __exit__(self, *args, **kwargs):
        assert self._lock_fd is not None
        fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
        os.close(self._lock_fd)
        self._lock_fd = None

    def _is_user_file(self, path):
        """Used as predicate when measuring user storage directories."""
        assert path.startswith(self._user_path + os.sep)
        path = path[len(self._user_path) + len(os.sep) :]
        # User files are under:
        # YYYY/MM/DD/NONCE/HASH (5 levels of nesting).
        # So a real user file has at least 6 components, which means it
        # must have at least 5 slashes.
        return path.count(os.sep) >= 5

    def copy(self, __id__, intake_path):
        """
        Copy a directory to user storage.
        Ensure that the user storage has room for the given number of files totaling the given number of bytes.
        If this is feasible by deleting previous user files, it will do so.
        Must be done while holding the lock.

        :param __id__: Chat or action ID.
        :param intake_path: Path to a directory that should be copied to the user storage.
        :raises OutOfStorageException: If there is not enough available file or bytes quota.
        :return: A list of `File`s from each file copied from `intake_path`.
        """
        assert (
            self._lock_fd is not None
        ), "Cannot perform this operation without holding the lock"
        want_num_files, want_num_bytes = self.measure_directory(intake_path)
        if want_num_files == 0:
            return ()  # Nothing to copy.
        if self._max_files_per_user <= want_num_files:
            raise self.OutOfStorageException(
                f"Cannot allocate storage for {want_num_files} files; maximum is {self._max_files_per_user} files per user"
            )
        if self._max_bytes_per_user <= want_num_bytes:
            raise self.OutOfStorageException(
                f"Cannot allocate storage for {want_num_bytes} bytes; maximum is {self._max_bytes_per_user} bytes per user"
            )
        disk_usage_free = shutil.disk_usage(self._user_path).free
        if (
            disk_usage_free
            <= want_num_bytes + self.MUST_KEEP_FREE_MARGIN_MEGABYTES * 1024 * 1024
        ):
            raise self.OutOfStorageException(
                f"Not enough free disk space for {want_num_bytes} bytes; current free space is {disk_usage_free} bytes and must keep at least {self.MUST_KEEP_FREE_MARGIN_MEGABYTES} megabytes free"
            )
        user_root_num_files, user_root_num_bytes = self.measure_directory(
            self._user_path,
            predicate=self._is_user_file,
        )
        user_root_remaining_files = self._max_files_per_user - user_root_num_files
        user_root_remaining_bytes = self._max_bytes_per_user - user_root_num_bytes
        while (
            user_root_remaining_files < want_num_files
            or user_root_remaining_bytes < want_num_bytes
        ):
            oldest_directory = None
            try:
                oldest_yyyy = next(
                    iter(
                        sorted(
                            f
                            for f in os.listdir(self._user_path)
                            if len(f) >= 4 and f.isdigit()
                        )
                    )
                )
                oldest_mm = next(
                    iter(
                        sorted(
                            f
                            for f in os.listdir(
                                os.path.join(self._user_path, oldest_yyyy)
                            )
                            if len(f) == 2 and f.isdigit()
                        )
                    )
                )
                oldest_dd = next(
                    iter(
                        sorted(
                            f
                            for f in os.listdir(
                                os.path.join(self._user_path, oldest_yyyy, oldest_mm)
                            )
                            if len(f) == 2 and f.isdigit()
                        )
                    )
                )
                oldest_nonce = next(
                    iter(
                        sorted(
                            f
                            for f in os.listdir(
                                os.path.join(
                                    self._user_path,
                                    oldest_yyyy,
                                    oldest_mm,
                                    oldest_dd,
                                )
                            )
                            if len(f) == self.NUM_NONCE_ZEROS and f.isdigit()
                        )
                    )
                )
                oldest_directory = os.path.join(
                    self._user_path, oldest_yyyy, oldest_mm, oldest_dd, oldest_nonce
                )
            except StopIteration:
                raise self.OutOfStorageException(
                    f"Cannot find directory to clear in order to make enough room for new user storage ({want_num_files} files, {want_num_bytes} bytes)"
                )
            assert oldest_directory is not None
            if not shutil.rmtree.avoids_symlink_attacks:
                raise self.EnvironmentNeedsSetupException(
                    "Only supported on platforms with symlink-attack-resistant rmtree implementations"
                )
            shutil.rmtree(oldest_directory)
            for parent_directory in (
                os.path.join(self._user_path, oldest_yyyy, oldest_mm, oldest_dd),
                os.path.join(self._user_path, oldest_yyyy, oldest_mm),
                os.path.join(self._user_path, oldest_yyyy),
            ):
                if len(os.listdir(parent_directory)) == 0:
                    os.rmdir(parent_directory)
            user_root_num_files, user_root_num_bytes = self.measure_directory(
                self._user_path,
                predicate=self._is_user_file,
            )
            user_root_remaining_files = self._max_files_per_user - user_root_num_files
            user_root_remaining_bytes = self._max_bytes_per_user - user_root_num_bytes

        # We now have enough. Find new directory name.
        path_with_counter = None
        max_nonce = 10**self.NUM_NONCE_ZEROS - 1
        for nonce in range(1, min(self._max_files_per_user or max_nonce, max_nonce)):
            path_with_counter = os.path.join(
                self._user_path, self._date, str(nonce).zfill(self.NUM_NONCE_ZEROS)
            )
            try:
                os.makedirs(path_with_counter, mode=0o755, exist_ok=False)
            except FileExistsError:
                pass
            else:
                break
        if path_with_counter is None:
            raise self.OutOfStorageException("No free storage directory available!")
        id_str = str(__id__) if __id__ is not None else self._date
        id_hash = hashlib.sha512()
        id_hash.update(self._user.encode("utf-8"))
        id_hash.update(b"||||")
        id_hash.update(self._date.encode("utf-8"))
        id_hash.update(b"||||")
        id_hash.update(path_with_counter.encode("utf-8"))
        id_hash.update(b"||||")
        id_hash.update(str(uuid.uuid4()).encode("utf-8"))
        id_hash.update(b"||||")
        id_hash.update(id_str.encode("utf-8"))
        id_hash_component = (
            base64.b32encode(id_hash.digest()).decode("ascii").lower()[:12]
        )
        final_path = os.path.normpath(
            os.path.abspath(os.path.join(path_with_counter, id_hash_component))
        )

        # Now do the copy.
        # This doesn't use `shutil.copytree` because we explicitly avoid copying anything but regular files.
        user_files = []
        for dirpath, subdirs, subfiles in os.walk(
            intake_path, onerror=None, followlinks=False
        ):
            dirpath = os.path.normpath(os.path.abspath(dirpath))
            relative_dirpath = None
            if dirpath == intake_path:
                relative_dirpath = "."
            elif dirpath.startswith(intake_path + os.sep):
                relative_dirpath = dirpath[len(intake_path) + len(os.sep) :]
            else:
                assert False, f"Bad traversal: expected all paths to starts with {intake_path} but got path that does not: {dirpath}"
            assert relative_dirpath is not None
            assert not os.path.isabs(relative_dirpath)
            copy_dirpath = os.path.join(final_path, relative_dirpath)
            os.makedirs(copy_dirpath, mode=0o755, exist_ok=True)
            for subfile in subfiles:
                subfile_path = os.path.join(dirpath, subfile)
                subfile_relative_path = os.path.normpath(
                    os.path.join(relative_dirpath, subfile)
                )
                assert not os.path.isabs(subfile_relative_path)
                subfile_stat = os.stat(subfile_path, follow_symlinks=False)
                if not stat.S_ISREG(subfile_stat.st_mode):
                    continue  # Ignore non-regular files.
                subfile_copy = os.path.join(copy_dirpath, subfile)
                assert subfile_copy.startswith(self._storage_root_path + os.sep)
                subfile_url = f"{self._storage_root_url}/" + urllib.parse.quote(
                    subfile_copy[len(self._storage_root_path) + len(os.sep) :],
                    safe=os.sep,
                )
                shutil.move(subfile_path, subfile_copy, copy_function=shutil.copy)
                user_files.append(
                    self.File(
                        file_path=subfile_copy,
                        file_relative_path=subfile_relative_path,
                        file_url=subfile_url,
                        file_size=subfile_stat.st_size,
                    )
                )

        # We are done.
        return user_files
