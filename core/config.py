import logging, configparser, os, shutil

log = logging.getLogger('config')

def loadConfig():
    config = configparser.ConfigParser()

    conf_file = "test.conf"
    conf_file_default = "test.conf.default"
    if os.path.isfile(conf_file):
        #log.info("Using configuration file %s" % conf_file)
        ret = config.read(conf_file)
        if not ret:
            raise IOError("Configuration could not be read! Aborting")
    else:
        log.error("Configuration file does not exist! Creating new from default %s file " % conf_file)
        log.error("Edit new configuration file %s, and rerun the tests" % conf_file)
        shutil.copy(conf_file_default, conf_file)
        exit(1)

    return config




class suiteLoader:
    def __init__(self):
        self.value = 0 # Create a member variable 'value'

    def loadSuite(self, filename):
        log.info("Loading suite")
        self.file = open(filename, 'r')
        raw_suite = [line.strip() for line in self.file if line.strip()]
        if not raw_suite:
            log.error("Cannot read suite description file. Aborting!")
            raise

        suite=[]
        for line in raw_suite:
            if not line.startswith('#'):
                #print line
                #line consists of [class test_cases]
                class_tcs = line.split()
                #print class_tcs
                for id in class_tcs:
                    suite.append(id)

        return suite
