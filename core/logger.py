import logging


logging.basicConfig(

    filename="scanner.log",

    level=logging.INFO,

    format="%(asctime)s %(levelname)s %(message)s"

)


logger=logging.getLogger("VulnScanner")