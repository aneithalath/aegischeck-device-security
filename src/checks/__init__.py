# Checks package init
# Makes all check modules importable
from .os_check import evaluate_os_security
from .password_check import run_password_scan
from .permissions_check import run_permissions_audit
