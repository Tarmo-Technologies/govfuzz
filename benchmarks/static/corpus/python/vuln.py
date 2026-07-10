import os, subprocess, pickle, yaml, hashlib
import tarfile
from flask import render_template_string, request
def h(r):
    os.system("rm " + r.p)                      # EXPECT GF-404
    subprocess.call(r.c, shell=True)            # EXPECT GF-404
    pickle.loads(r.b)                           # EXPECT GF-421
    yaml.load(r.t)                              # EXPECT GF-421
    eval(r.e)                                   # EXPECT GF-420
    db.execute("SELECT * FROM t WHERE i=" + r.i)  # EXPECT GF-419
    hashlib.md5(r.d)                            # EXPECT GF-422
    api_key = "AKIAsecretvalue123"              # EXPECT GF-429
    tarfile.open(r.archive).extractall(r.dest)  # EXPECT GF-542
    render_template_string(request.args.get("tpl"))  # EXPECT GF-543

def django_security_settings(env, config):
    SECURE_SSL_REDIRECT = False                 # EXPECT GF-541
    SECURE_SSL_REDIRECT = env.bool("SECURE_SSL_REDIRECT", default=False)  # EXPECT GF-541
    SECURE_SSL_REDIRECT = config("SECURE_SSL_REDIRECT", default=False, cast=bool)  # EXPECT GF-541
    env_schema = Env(
        DD_SECURE_SSL_REDIRECT=(bool, False),
    )
    SECURE_SSL_REDIRECT = env("DD_SECURE_SSL_REDIRECT")  # EXPECT GF-541
