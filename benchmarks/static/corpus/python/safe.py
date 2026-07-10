import subprocess, tarfile, yaml, hashlib
from flask import render_template_string
def h(r):
    subprocess.run(["ls", "-l"])                # safe: no shell
    eval("1 + 2")                               # safe: literal
    yaml.safe_load(r.t)                         # safe loader
    db.execute("SELECT * FROM t WHERE i=%s", (r.i,))  # parameterized
    hashlib.sha256(r.d)                         # strong hash
    note = "call os.system() only on trusted input"   # api name in a string
    tarfile.open(r.archive).extractall(r.dest, filter="data")
    tar = tarfile.open(r.archive)
    tar.extract(r.member, r.dest, filter=tarfile.data_filter)
    render_template_string("<p>{{ name }}</p>", name=r.name)

def django_security_settings(env, config):
    SECURE_SSL_REDIRECT = True
    SECURE_SSL_REDIRECT = env.bool("SECURE_SSL_REDIRECT", default=True)
    SECURE_SSL_REDIRECT = config("SECURE_SSL_REDIRECT", default=True, cast=bool)
    text = "SECURE_SSL_REDIRECT = False"
