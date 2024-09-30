import datetime
import re
import typing


class UpdateCheck:
    """
    Check for updates.
    """

    RELEASES_URL = (
        "https://github.com/EtiennePerot/safe-code-execution/releases.atom"
    )
    USER_URL = "https://github.com/EtiennePerot/safe-code-execution/"
    ENABLED = True
    SELF_VERSION = None
    LAST_UPDATE_CHECK = None
    LAST_UPDATE_CACHE = None
    UPDATE_CHECK_INTERVAL = datetime.timedelta(days=3)
    VERSION_REGEX = re.compile(r"<title>\s*(v?\d+(?:\.\d+)+)\s*</title>")

    class VersionCheckError(Exception):
        pass

    @staticmethod
    def _parse_version(version_str):
        return tuple(int(c) for c in version_str.strip().removeprefix("v").split("."))

    @staticmethod
    def _format_version(version):
        return "v" + ".".join(str(c) for c in version)

    @staticmethod
    def _compare(version_a, version_b):
        """
        Returns -1 if version_a < version_b, 0 if equal, 1 if greater.
        """
        for a, b in zip(version_a, version_b):
            if a < b:
                return -1
            if a > b:
                return 1
        return len

    @classmethod
    def disable(cls):
        cls.ENABLED = False

    @classmethod
    def init_from_frontmatter(cls, file_with_frontmatter):
        if not cls.ENABLED:
            return
        with open(file_with_frontmatter, "rb") as f:
            contents = f.read().decode("ascii").strip()
        if not contents.startswith('"""'):
            raise cls.VersionCheckError(
                f"Malformed file contents: {contents[:min(8, len(contents))]}[...]"
            )
        contents = contents[len('"""'):].strip()
        version = None
        for line in contents.split("\n"):
            line = line.strip()
            if line == '"""':
                break
            if line.startswith("version:"):
                if version is not None:
                    raise cls.VersionCheckError(
                        f"Multiple 'version' lines found: {version} and {line}"
                    )
                version = line[len("version:"):].strip()
        if version is None:
            raise cls.VersionCheckError("Version metadata not found")
        cls.SELF_VERSION = cls._parse_version(version)

    @classmethod
    def _get_current_version(cls):
        assert cls.SELF_VERSION is not None, "UpdateCheck.init_from_frontmatter must be called first."
        return cls.SELF_VERSION

    @classmethod
    def need_check(cls):
        if cls.LAST_UPDATE_CHECK is None:
            return True
        return (
            datetime.datetime.now() - cls.LAST_UPDATE_CHECK >= cls.UPDATE_CHECK_INTERVAL
        )

    @classmethod
    def _get_latest_version(cls):
        if not cls.need_check():
            if type(cls.LAST_UPDATE_CACHE) is type(()):
                return cls.LAST_UPDATE_CACHE
            raise cls.LAST_UPDATE_CACHE
        try:
            try:
                releases_xml = urllib.request.urlopen(url=cls.RELEASES_URL).read()
            except urllib.error.HTTPError as e:
                cls.LAST_UPDATE_CACHE = cls.VersionCheckError(
                    f"Failed to retrieve latest version: {e} (URL: {cls.RELEASES_URL})"
                )
                raise cls.LAST_UPDATE_CACHE
            latest_version = None
            for match in cls.VERSION_REGEX.finditer(releases_xml.decode("utf-8")):
                version = cls._parse_version(match.group(1))
                if latest_version is None or cls._compare(version, latest_version) == 1:
                    latest_version = version
            if latest_version is None:
                cls.LAST_UPDATE_CACHE = cls.VersionCheckError(
                    f"Failed to retrieve latest version: no release found (URL: {cls.RELEASES_URL})"
                )
                raise cls.LAST_UPDATE_CACHE
            cls.LAST_UPDATE_CACHE = latest_version
            return latest_version
        finally:
            cls.LAST_UPDATE_CHECK = datetime.datetime.now()

    @classmethod
    def get_newer_version(cls) -> typing.Optional[str]:
        """
        Check for the latest version and return it if newer than current.

        :raises VersionCheckError: If there was an error checking for version.
        :return: The latest version number if newer than current, else None.
        """
        if not cls.ENABLED:
            return None
        try:
            current_version = cls._get_current_version()
        except cls.VersionCheckError as e:
            raise e.__class__(f"Checking current version: {e}")
        try:
            latest_version = cls._get_latest_version()
        except cls.VersionCheckError as e:
            raise e.__class__(f"Checking latest version: {e}")
        if cls._compare(current_version, latest_version) == -1:
            return cls._format_version(latest_version)
        return None
