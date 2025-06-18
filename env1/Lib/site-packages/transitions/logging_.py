import logging


class TransitionLog(object):

    def __init__(self, transition):
        self.transition = transition

    def to_seq(self):
        pass


class Logger(object):

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.addHandler(logging.NullHandler())

    def sequence_diagram(self):
        pass

    def log(self):
        self.logger.info()
