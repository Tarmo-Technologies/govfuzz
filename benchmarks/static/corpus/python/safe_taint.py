# Hard negatives (Python, indentation-delimited): each function takes a tainted
# input to a sink yet is safe. No EXPECT — any finding is a precision-breaking FP.
# (Sanitizer clearing is a taint-engine property proven in the Go corpus + unit
# tests; Python's os.system/popen are always-flagged heuristics, so a "sanitized
# os.system" is not a clean negative here — it is deliberately omitted.)
import subprocess


def param_query(user_query, cursor):
    cursor.execute("SELECT * FROM t WHERE x=?", (user_query,))  # parameterized


def list_form(user_input):
    subprocess.run(["ls", "-l", user_input])  # no shell=True -> not a shell


def literal_path():
    open("/etc/hosts")  # literal path


def pathlib_method(input_path):
    # `.open()` is a pathlib METHOD on an already-built Path, not the builtin
    # open() sink — even though `input_path` is a source, this must not fire.
    with input_path.open() as f:
        return f.read()


# A name that REFERENCES where a secret lives (its env-var name) assigned the
# env-var NAME is the correct, safe pattern — not a hardcoded secret.
NVD_API_KEY_ENV_VAR = "NVD_API_KEY"
api_key_name = "SERVICE_API_KEY"


class Evaluator:
    # A method DEFINITION named `eval` is not a call to the builtin eval().
    def eval(self, expr, want_text=False):
        return len(expr)
