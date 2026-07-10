# M23 Phase 2: interprocedural taint for Python (indentation-delimited). A
# source-like parameter reaching a command sink (os.system / subprocess shell=True)
# is GF-304 (proven flow), superseding the always-on GF-404 heuristic at that site.
import logging, os, subprocess, shlex


def run(user_input):
    os.system(user_input)  # EXPECT GF-304


def dispatch(user_query):
    forward(user_query)


def forward(arg):
    os.system(arg)  # EXPECT GF-304


def clean(user_path):
    v = shlex.quote(user_path)
    os.system(v)  # EXPECT GF-404


def sub(user_data):
    subprocess.run(user_data, shell=True)  # EXPECT GF-304


def log_user(user_input, logger):
    logger.warning(user_input)  # EXPECT GF-544
    logger.info("fixed")
    safe = sanitize_for_log(user_input)
    logger.error(safe)
