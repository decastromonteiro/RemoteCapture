import argparse
import os

parser = argparse.ArgumentParser()

parser.add_argument("-f", "--file", help="Specify File Path to use as a FIFO file")
parser.add_argument("-s", "--server", help="Specify server IP or domain name to use SSH")
parser.add_argument("-u", "--user", help="Specify User to log into server via SSH")
parser.add_argument("-i", "--interface", help="Specify interface to be monitored on remote server")
parser.add_argument("-bpf", "--bpf_filter", help="Specify BPF filter ao apply to tcpdump capture")

args = parser.parse_args()


def main():
    file_path = args.file if args.file else os.path.abspath("/tmp/remote_capture")
    server = args.server if args.server else "10.10.10.1"
    user = args.user if args.user else "root"
    interface = args.interface if args.interface else "eth0"
    bpf_filter = args.bpf_filter if args.bpf_filter else ""

    os.system("mkfifo {}".format(file_path))
    os.system("sudo wireshark -k -i {} &".format(file_path))
    os.system('ssh {user}@{server} "tcpdump -s 0 -U -w - -i {interface} {bpf_filter}" > {file_path}'.format(
        user=user,
        server=server,
        interface=interface,
        bpf_filter=bpf_filter,
        file_path=file_path
    ))


if __name__ == "__main__":
    main()
