import argparse
import importlib
import os
import os.path
import re
import sys

if __name__ != "__main__":
    print("This file is meant to run as a script.", file=sys.stderr)
    sys.exit(2)

_REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

parser = argparse.ArgumentParser(description="Check or build Open WebUI output files.")
parser.add_argument(
    "--mode",
    choices=("check", "build"),
    default="check",
    help="Whether to [check] the open-webui output files against the codebase, or to [build] and overwrite them.",
)
args = parser.parse_args()

VERSION = None
with open(os.path.join(_REPO_DIR, "build/version.txt"), "rb") as f:
    VERSION = tuple(int(c) for c in f.read().decode("ascii").strip().split("."))

_FRONTMATTER_HEADER = {
    "id": "run_code",
    "title": "Run code",
    "description": "Run arbitrary Python or Bash code safely in a gVisor sandbox.",
    "author": "Etienne Perot",
    "author_url": "https://github.com/EtiennePerot/safe-code-execution",
    "funding_url": "https://github.com/EtiennePerot/safe-code-execution",
    "version": ".".join(str(c) for c in VERSION),
    "license": "Apache-2.0",
}

_FUNCTION_COMMENT_HEADER = """
# NOTE: If running Open WebUI in a container, you *need* to set up this container to allow sandboxed code execution.
# Please read the docs here:
#
#   https://github.com/EtiennePerot/safe-code-execution/blob/master/README.md
#
# This is an OpenWebUI *function*. It can run code within LLM-generated code blocks.
# If you are looking for an OpenWebUI *tool* to allow the LLM to run its own code,
# see here instead: https://openwebui.com/t/etienneperot/run_code/
"""

_TOOL_COMMENT_HEADER = """
# NOTE: If running Open WebUI in a container, you *need* to set up this container to allow sandboxed code execution.
# Please read the docs here:
#
#   https://github.com/EtiennePerot/safe-code-execution/blob/master/README.md
#
# This is an OpenWebUI *tool*. It allows an LLM to generate and call code on its own.
# If you are looking for an OpenWebUI *function* to allow you to manually execute blocks
# of code in the LLM output, see here instead:
# https://openwebui.com/f/etienneperot/run_code/
"""

_COMMON_COMMENT_HEADER = """
#
# See https://github.com/EtiennePerot/safe-code-execution for more info.
#
# Protip: You can test this manually by running it as a Python script, like so:
# (Run this inside the Open WebUI container)
#
#   python3 run_code.py --self_test
#
# This will simulate that OpenWebUI would do if it asked this tool to evaluate the Python code `print("Hello world!")`.
# This can be useful when setting up this tool to verify that it works in your environment.
# You can also use it for one-off code execution like this:
#
#   echo 'print("Hello world!")' | python3 run_code.py
#
"""

OUTPUT_FILES = {
    "open-webui/functions/run_code.py": {
        "template_path": "src/openwebui/functions/run_code.py",
        "frontmatter": _FRONTMATTER_HEADER,
        "comment_header": _FUNCTION_COMMENT_HEADER + _COMMON_COMMENT_HEADER,
    },
    "open-webui/tools/run_code.py": {
        "template_path": "src/openwebui/tools/run_code.py",
        "frontmatter": _FRONTMATTER_HEADER,
        "comment_header": _TOOL_COMMENT_HEADER + _COMMON_COMMENT_HEADER,
    },
}

_PLAIN_IMPORT_RE = re.compile(r"^import ([_.\w]+(?: as [_\w]+)?(?:, [_.\w]+(?: as [_\w]+)?)*)$")
_FROM_IMPORT_RE = re.compile(r"^from [_.\w]+ import ([_\w]+(?: as [_\w]+)?(?:, [_\w]+(?: as [_\w]+)?)*)$")
def get_import_names(import_line):
    comment_index = import_line.find("#")
    if comment_index != -1:
        import_line = import_line[:comment_index]
    import_line = import_line.rstrip()
    plain_import_match = _PLAIN_IMPORT_RE.match(import_line)
    if plain_import_match:
        symbols = []
        for import_symbol in plain_import_match.group(1).split(","):
            import_symbol = import_symbol.strip()
            if " as " in import_symbol:
                symbol_name = import_symbol.split(" as ")[1]
            else:
                symbol_name = import_symbol
            symbol_name = symbol_name.strip()
            components = []
            for component in symbol_name.split("."):
                components.append(component)
                symbols.append(".".join(components))
        return tuple(symbols)
    from_import_match = _FROM_IMPORT_RE.match(import_line)
    if from_import_match:
        symbols = []
        for import_symbol in from_import_match.group(1).split(","):
            import_symbol = import_symbol.strip()
            if " as " in import_symbol:
                symbol_name = import_symbol.split(" as ")[1]
            else:
                symbol_name = import_symbol
            symbol_name = symbol_name.strip()
            assert symbol_name not in symbols, f"Duplicate imported symbol: {symbol_name}"
            symbols.append(symbol_name)
        assert len(symbols) > 0, f"No symbols imported: {import_line}"
        return tuple(symbols)
    assert not import_line.startswith("import ") and not import_line.startswith("from "), f"Unrecognized import line: {import_line}"
    return None

def process_file(
    template_path,
    frontmatter,
    comment_header,
):
    inline_import_re = re.compile(r"^from ([_.\w]+) import ([_\w]+(?:, [_\w]+)*)\s*# INLINE_IMPORT.*$")
    inline_imported_module_names = set()
    inline_imported_symbol_names = set()

    previous_path = sys.path[:]
    sys.path.append(os.path.join(_REPO_DIR, "build"))
    try:
        empty_module = importlib.import_module("empty")
    finally:
        sys.path = previous_path

    def process_inline_import(inline_import):
        match = inline_import_re.match(inline_import)
        assert match is not None, f"Invalid inline import: {inline_import}"
        module_name, imported_names_str = match.groups()
        assert module_name not in inline_imported_module_names, f"Duplicate inline import: {module_name}"
        inline_imported_module_names.add(module_name)
        want_imported_names = frozenset(n.strip() for n in imported_names_str.split(","))
        search_paths = (
            os.path.join(_REPO_DIR, "src", module_name.replace(".", os.sep), "__init__.py"),
            os.path.join(_REPO_DIR, "src", module_name.replace(".", os.sep) + ".py"),
        )
        module_path = None
        for search_path in search_paths:
            if os.path.exists(search_path):
                assert module_path is None, f"Multiple matching files when importing {module_name}"
                module_path = search_path
        assert module_path is not None, f"No matching file when importing {module_name}"
        previous_path = sys.path[:]
        sys.path.append(os.path.join(_REPO_DIR, "src"))
        try:
            imported = importlib.import_module(module_name)
        except Exception as e:
            raise e.__class__(f"Failed to import {module_name}: {e}")
        finally:
            sys.path = previous_path
        imported_symbol_names = set()
        module_imports = []
        module_body = []
        with open(module_path, "r", encoding="ascii") as module_file:
            for module_line in module_file.read().splitlines():
                imported_names = get_import_names(module_line)
                if imported_names is None:
                    module_body.append(module_line)
                else:
                    module_imports.append(module_line)
                    imported_symbol_names.update(imported_names)
        got_imported_name = set()
        for imported_name in imported.__dict__.keys():
            if imported_name in empty_module.__dict__:
                continue
            if imported_name in imported_symbol_names:
                continue
            if imported_name in want_imported_names:
                got_imported_name.add(imported_name)
                continue
            raise ValueError(f"Module '{module_name}' imports symbol '{imported_name}' which is not declared in inline import line '{inline_import}'")
        for imported_name in want_imported_names:
            assert imported_name in got_imported_name, f"Module '{module_name}' was expected to declare symbol '{imported_name}' but it did not"
        return module_imports, module_body

    with open(template_path, "rb") as template_f:
        template = template_f.read().decode("ascii")
    ordered_imports = []
    output_body = []
    for template_line in template.splitlines():
        if "# ::" in template_line:
            continue
        lines = [template_line]
        if "# INLINE_IMPORT" in template_line:
            extra_imports, module_body = process_inline_import(template_line)
            ordered_imports.extend(extra_imports)
            lines = module_body + ["", ""]
        for line in lines:
            assert "# INLINE_IMPORT" not in line, "Recursive inline imports not supported yet"
            assert "# ::" not in line, "Cannot use '# ::' outside of main template"
            if line.startswith("import ") or line.startswith("from "):
                ordered_imports.append(line)
            else:
                output_body.append(line)
    already_imported = set()
    combined_imports = []
    for imp in ordered_imports:
        if imp in already_imported:
            continue
        already_imported.add(imp)
        combined_imports.append(imp)
    output = "\n\n".join((
        '"""\n' + '\n'.join(f"{k}: {v}" for k, v in frontmatter.items()) + '\n"""',
        comment_header,
        "\n".join(combined_imports),
        "\n".join(output_body),
    )) + "\n"
    while "\n\n\n\n" in output:
        output = output.replace("\n\n\n\n", "\n\n\n")
    return output

error = False
for output_path, arguments in OUTPUT_FILES.items():
    output_path = os.path.join(_REPO_DIR, output_path)
    print(f"Processing file: {output_path}", file=sys.stderr)
    with open(output_path, "rb") as output_f:
        current_contents = output_f.read().decode("ascii")
    want_contents = process_file(**arguments)
    if args.mode == "check":
        if current_contents != want_contents:
            print(f"ERROR: Contents of {output_path} do not match the codebase; use --mode=build to overwrite.", file=sys.stderr)
            error = True
    elif args.mode == "build":
        if current_contents != want_contents:
            with open(output_path + ".tmp", "wb") as output_f:
                output_f.write(want_contents.encode("ascii"))
            os.rename(output_path + ".tmp", output_path)
    else:
        raise ValueError(f"Invalid mode: {args.mode}")
if error:
    sys.exit(1)
print("OK", file=sys.stderr)
sys.exit(0)
