import argparse
import sys
import re
import csv
import hashlib

salt = "s41t"

def get_options(cmd_args=None):
    """
    Parse command line arguments
    """
    cmd_parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    cmd_parser.add_argument(
        '-i',
        '--input_file',
        help="""a log file to be cleaned up""",
        type=str,
        default='')
    cmd_parser.add_argument(
        '-s',
        '--salt',
        help="""the salt for anonymizing IPs [optional, defaults to hardcoded one]""",
        type=str,
        default=salt)

    args = cmd_parser.parse_args(cmd_args)

    options = {}
    options['input_file']   = args.input_file
    options['salt']         = args.salt

    return options

# the salt is just to avoid basic rainbow tables and possibly change different runs with different salts
def anonIP(salt,ip):
    digest  = hashlib.new('sha256',salt + ip).hexdigest()
    first   = hash(digest[:16])%255
    second  = hash(digest[17:32])%255
    third   = hash(digest[33:52])%255
    fourth  = hash(digest[52:65])%255

    r       = str(first) + "." + str(second) + "." + str(third) + "." + str(fourth)
    return r

def main(options):

    if (options['input_file']):
        csv_file = open(options['input_file'])
        csv_reader  = csv.reader(csv_file, delimiter=',')
        out_data = []
        ln = 0
        IPs     = {}

        for line in csv_reader:
            if (ln == 0):
                ln = ln + 1
                out_data.append(line)
                continue
            out = line

            SrcIP   = anonIP(options['salt'],line[1])
            DstIP   = anonIP(options['salt'],line[3])

            FlowID  = out[0].split("-")
            FlowID[0]   = SrcIP
            FlowID[1]   = DstIP
            out[0]  = "-".join(FlowID)  # FlowID
            out[1]  = SrcIP     # SrcIP
            out[3]  = DstIP     # DstIP


            out_data.append(out)

        csv_file.close()

        o = open(options['input_file'] + ".cleaned","w")
        csw = csv.writer(o,delimiter=',')
        for l in out_data:
            csw.writerow(l)
        o.close()
        print("anonymization completed")

if __name__ == "__main__":
    sys.exit(main(get_options()))