"""
Job dispatcher — routes job operations to either the local (in-process)
implementation or the managed (remote API) implementation based on the
TRUFFLE_MODE configuration.

Public interface (unchanged from previous version):
  start_scan(params) -> str (job_id)
  get(job_id) -> Optional[dict]
  start_iam_discover(params) -> str
  start_idc_discover(params) -> str
  start_idc_apply(params) -> str
"""

from . import config

if config.is_managed_mode():
    from ._jobs_managed import (  # noqa: F401
        start_scan,
        get,
        start_iam_discover,
        start_iam_migrate,
        start_idc_discover,
        start_idc_apply,
    )
else:
    from ._jobs_local import (  # noqa: F401
        start_scan,
        get,
        start_iam_discover,
        start_idc_discover,
        start_idc_apply,
    )
