import logging
import urllib3
from urllib3 import Retry


def setup_logging():
    # set up logging to file - see previous section for more details
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                        datefmt='%m-%d %H:%M:%S',
                        filename='myapp.log',
                        filemode='w')
    # define a Handler which writes INFO messages or higher to the sys.stderr
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    # set a format which is simpler for console use
    formatter = logging.Formatter('%(asctime)s %(name)-12s\t\t %(levelname)-8s %(message)s')
    # tell the handler to use this format
    console.setFormatter(formatter)
    # add the handler to the root logger
    logging.getLogger().addHandler(console)

    return logging.getLogger("api_call_times")


def setup_http_pool():
    retries = Retry(total=1000, connect=5, read=2, redirect=5)
    urllib3.util.make_headers(keep_alive=True)

    return urllib3.PoolManager(num_pools=500,
                               maxsize=10000,
                               retries=retries,
                               block=True)


api_call_times_logger = setup_logging()
http_pool_manager = setup_http_pool()
