"""pytest 公共夹具与日志：让每个用例打印输入与判定依据。"""

import logging


def pytest_configure(config):
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    )
    root = logging.getLogger("soc.test")
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    root.propagate = False
