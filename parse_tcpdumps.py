import datetime
import sys
import time

# Constants for connection begin and end -- it doesn't really matter
# what the value is
SYN = True
FIN = False

# Format string of the tcpdump format's timestamps
TIME_FORMAT = '%I:%M:%S.%f'

def filter_tcpdump(dump_file):
    '''
    Takes a file in tcpdump format, returning a generator of all
    connection beginnings or ends, as (time, ip, type) tuples.
    '''
    with open(dump_file) as f:
        for line in f:
            syn = 'Flags [S]' in line
            fin = 'Flags [F.]' in line
            if syn or fin:
                parts = line.split()
                timestamp = datetime.datetime.strptime(parts[0], TIME_FORMAT)
                yield (timestamp, parts[2], SYN if syn else FIN)

def main():
    input_file = sys.argv[1]
    begin_times, end_times = {}, {}
    first_time = None # time of first connection
    for timestamp, client, conn in filter_tcpdump(input_file):
        if first_time is None:
            first_time = timestamp
        if conn == SYN:
            begin_times[client] = timestamp
        else:
            # We're only concerned about the client sending FIN-ACK,
            # so we'll end up with a single entry from the server
            # (5.6.7.8) -- we can ignore that entry
            end_times[client] = timestamp
    for client, timestamp in begin_times.iteritems():
        start = (timestamp - first_time).total_seconds()
        if client in end_times:
            print('{0}\t{1}'.format(
                    start, (end_times[client] - timestamp).total_seconds()
                    )
                  )
        else:
            print('{0}\t200'.format(start))

if __name__ == '__main__':
    main()
