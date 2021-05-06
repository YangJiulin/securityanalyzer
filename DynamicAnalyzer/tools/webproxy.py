""""生成mitm证书并启动代理服务"""
import logging
import os
from pathlib import Path
import subprocess
import time
import signal
from securityanalyzer.utils import is_file_exists

logger = logging.getLogger(__name__)


def stop_httptools(pid):
    """Kill lyrebird"""
    # HTTP Proxy Kill Request
    try:
        os.kill(pid,signal.SIGKILL)
    except Exception:
        pass


def start_proxy(port):
    """Start HTTPtools in Proxy Mode."""
    argz = ['lyrebird','-b',
            '--mock', '9090',
            '--proxy', str(port)]
    fnull = open(os.devnull, 'w')
    process = subprocess.Popen(argz, stdout=fnull, stderr=subprocess.STDOUT)
    return process.pid



def create_ca():
    """Generate CA on first run."""
    argz = ['mitmdump', '-n']
    subprocess.Popen(argz,
                     stdin=None,
                     stdout=None,
                     stderr=None,
                     close_fds=True)
    time.sleep(2)


def get_ca_file():
    """Get CA Dir."""
    from mitmproxy import ctx
    ca_dir = Path(ctx.mitmproxy.options.CONF_DIR).expanduser()
    ca_file = os.path.join(str(ca_dir), 'mitmproxy-ca-cert.pem')
    if not is_file_exists(ca_file):
        create_ca()
    return ca_file
