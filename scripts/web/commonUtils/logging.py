import logging

def configure_logging():
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("script.log", mode="a"),
        ]
    )
    logging.info("Logging initialized.")
