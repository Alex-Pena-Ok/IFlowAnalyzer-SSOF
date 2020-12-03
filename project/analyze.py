import sys
import json
import time

from analProgram import analyzeProgram


def usage():
    sys.stderr.write('Usage: analyze program.json vulnPattern.json\n')
    sys.exit(1)


if __name__ == '__main__':
    start_time = time.time()

    if len(sys.argv) != 3:
        usage()
    programPath = sys.argv[1]
    programJson = open(programPath).read()

    vulnPatternPath = sys.argv[2]
    vulnPatternJson = open(vulnPatternPath).read()

    programJson = json.loads(programJson)
    vulnPattern = json.loads(vulnPatternJson)

    analyzeProgram(programJson, vulnPattern)
    print("--- %s seconds ---" % (time.time() - start_time))

