from scapy.layers.http import HTTPRequest, HTTPResponse
from colorama import init, Fore, Back
from scapy.all import *
import argparse
import random
import sys

init()  # Initialize the colors


class Colors:

    RESET = Fore.RESET
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    BLUE = Fore.BLUE
    WHITE = Fore.WHITE

    def getFore():
        COLORS = (
            Colors.RED, Colors.GREEN, Colors.YELLOW,
            Colors.CYAN, Colors.MAGENTA, Colors.BLUE, Colors.WHITE
        )
        return COLORS[random.randint(0, 6)]

    def getBack():
        COLORS_BG = (
            Back.RED, Back.GREEN, Back.YELLOW,
            Back.BLUE, Back.CYAN, Back.MAGENTA,
            Back.BLACK, Back.WHITE
        )
        return COLORS_BG[random.randint(0, 7)]

class SNIFF:
	def __init__(self, count=0, passed_filters='port 80 and tcp', outfile='', iface=None, isHTTP=False):
		self.count = count
		if passed_filters != 'port 80 and tcp' or passed_filters != 'tcp and port 80':
			self.filter = passed_filters
		else:
			self.filter = passed_filters
		self.outfile = outfile
		if '.pcap' not in self.outfile and outfile != '':
			self.outfile += '.pcap'
		self.counter = 0
		self.interface = iface
		self.isHTTP = isHTTP
	def run(self):
		print(f"{Colors.RED}[*]{Colors.RESET} Sniffing has begun{f' on interface {Colors.CYAN}{self.interface}' if self.interface != None else ''}!\n")
		
		if self.count != 0 or (self.filter != 'port 80 and tcp' or self.filter != 'tcp and port 80') or self.outfile != '' or self.interface != None:
			print(f"\n{Colors.GREEN}[*]{Colors.RESET} Following arguments were provided:\n")
			if self.count != 0:
				print(f"{Colors.BLUE}[+]{Colors.RESET} Count = {Colors.YELLOW}{self.count}")
			print(f"{Colors.BLUE}[+]{Colors.RESET} Filter = {Colors.YELLOW}{self.filter}")
			print(f"{Colors.BLUE}[+]{Colors.RESET} Output To File Enabled = {f'{Colors.GREEN}Yes.' if self.outfile != '' else f'{Colors.RED}No.'}")
			if self.outfile != '':
				print(f"{Colors.BLUE}[+]{Colors.RESET} Output File Name = {Colors.YELLOW} {self.outfile}")
			if self.interface != None:
				print(f"{Colors.BLUE}[+]{Colors.RESET} Interface = {Colors.MAGENTA}{self.interface}{Colors.RESET}")
			print(f"{Colors.BLUE}[+]{Colors.RESET} isHTTP = {f'{Colors.GREEN}Yes.' if self.isHTTP else f'{Colors.RED}No.'}")
			print(f'{Colors.RESET}\n') # Aesthetics
		try:
			sniff(
					count = self.count,
					prn=self.packet_analysis,
					filter=self.filter,
					iface=self.interface
				)
		except ValueError:
			print(f"{Colors.RED}[!]{Colors.RESET} Network interface:{Colors.RED} {self.interface}{Colors.RESET} not found on system")
			sys.exit(-1)
	def write_to_pcap(self, packet):
		wrpcap(self.outfile, packet, append=True)
	def packet_analysis(self, packet):
		if packet.haslayer(HTTPRequest):
			sent_to = packet[HTTPRequest].Host.decode()
			path_to = packet[HTTPRequest].Path.decode()
			sent_frm= packet[IP].src
			method  = packet[HTTPRequest].Method.decode()
			print(f"{Colors.GREEN}[*] {Colors.CYAN}HTTP{Colors.RESET} Request:{Colors.CYAN}{method} {Colors.MAGENTA}{path_to}{Colors.RESET} on {Colors.BLUE}{sent_to}{Colors.RESET} from {Colors.YELLOW}{sent_frm}{Colors.RESET}")
			self.counter += 1
			if method == "POST":
				try:
					print(f"{Colors.RED}[^] {Colors.RESET}Data sent with {Colors.CYAN}POST{Colors.RESET} Request: {Colors.RED}{(packet[Raw].load).decode()}{Colors.RESET}")
				except:
					pass
		elif packet.haslayer(HTTPResponse):
			status_code = packet[HTTPResponse].Status_Code.decode()
			phrase = packet[HTTPResponse].Reason_Phrase.decode()
			print(f"{Colors.RED}[=]{Colors.CYAN} HTTP {Colors.RESET}Response: Status Code: {Colors.CYAN}{status_code}{Colors.RESET} Phrase: {Colors.BLUE}{phrase}.")
		else:
			self.print_Packet(packet)
		if self.count != 0:
			if self.counter == self.count:
				printCount()
		if self.outfile != '':
			self.write_to_pcap(packet)		
	def print_Packet(self, packet):
		protocol = ''
		flags = {
			    'F': 'FIN',
			    'S': 'SYN',
			    'R': 'RST',
			    'P': 'PSH',
			    'A': 'ACK',
			    'U': 'URG',
			    'E': 'ECE',
			    'C': 'CWR'
			}
		if self.isHTTP == False:
			if self.filter != 'port 80 and tcp' and self.filter != 'tcp and port 80':
				if not packet.haslayer(HTTPRequest):
					if packet.haslayer(TCP):
						protocol = 'TCP'
						tcp_flags = [flags[i] for i in packet.sprintf('%TCP.flags%')]
						tcp_flags = '-'.join(tcp_flags)
					elif packet.haslayer(UDP):
						protocol = 'UDP'
					elif packet.haslayer(ARP):
						protocol = 'ARP'
					elif packet.haslayer(ICMP):
						protocol = 'ICMP'
					try:
						print(f"{Colors.GREEN}[*] {Colors.CYAN}{protocol}{Colors.RESET} Packet: Sent From {Colors.MAGENTA}{packet[IP].src}:{packet[TCP].sport}{Colors.RESET} to {Colors.BLUE}{packet[IP].dst}:{packet[TCP].dport}{Colors.RESET}{f'{Colors.YELLOW} {tcp_flags} Packet' if tcp_flags != '' else '' }{Colors.RESET}")
					except:
						print(f"{Colors.GREEN}[*] {Colors.CYAN}{protocol}{Colors.RESET} Packet: Sent From {Colors.MAGENTA}{packet[IP].src}{Colors.RESET} to {Colors.BLUE}{packet[IP].dst}{Colors.RESET}")
					if packet.haslayer(TCP) and packet.haslayer(Raw):
						dPort = packet[TCP].dport
						sPort = packet[TCP].sport
						if dPort == 20 or dPort == 20 or dPort == 21 or sPort == 21:
							method = "FTP"
						elif dPort == 22 or sPort == 22:
							method = "SSH/SFTP"
						print(f"{Colors.GREEN}[*] {Colors.CYAN}{method}{Colors.RESET} Packet: Sent From {Colors.MAGENTA}{packet[IP].src}{Colors.RESET} to {Colors.BLUE}{packet[IP].dst}{Colors.RESET}")

	def printCount(self):
		print(f"\n{Colors.GREEN}[+]{Colors.RESET} Successfully captured {Colors.RED}{self.count}{Colors.RESET} packets{f' and stored in file {Colors.GREEN}{self.outfile}.'if self.outfile!=''else'.'}")
		sys.exit(0)

class Args:
	def __init__(self):
		self.parser = argparse.ArgumentParser(
		    formatter_class=argparse.RawTextHelpFormatter,
		    description=f"{Colors.getFore()}METH - {Colors.getFore()}HTTP Packet Sniffer.{Colors.RESET}"
		)
		self.parser.add_argument(
			'-c',
			'--count',
			nargs=1,
			type=int,
			help="Numbers of packets that you need to capture (0 = Infinity)"
		)
		self.parser.add_argument(
			'-f',
			'--filter',
			nargs='+',
			type=str,
			help="The Berkeley Packet Filter (BPF) that you need to set. (Default is: 'port 80 and tcp') NOTE: You need to Specify them as a string"
		)
		self.parser.add_argument(
			'-H',
			'--http-only',
			action='store_true',
			help="Limit the results to display only http/https packets"
		)
		self.parser.add_argument(
			'-o',
			'--outfile',
			nargs=1,
			help="Store all the sniffed packet to a .pcap file (You don't need Specify the extension, just the file name.)"
		)
		self.parser.add_argument(
			'-i',
			'--interface',
			nargs=1,
			help="Specify an interface to sniff traffic on"
		)
	def parse(self):
		return self.parser.parse_args()

def banner():
    print(f"""
{Colors.CYAN}|  \\/  | ____|_   _| | | |
| |\\/| |  _|   | | | |_| |
| |  | | |___  | | |  _  |
|_|  |_|_____| |_| |_| |_|
\tBy: {Colors.CYAN}@{Colors.YELLOW}The{Colors.RED}Flash{Colors.WHITE}2k{Colors.YELLOW}/{Colors.CYAN}@{Colors.RED}hash3lizer{Colors.RESET}
{Colors.getFore()}HTTP {Colors.getFore()}Packet {Colors.getFore()}Sniffer{Colors.RESET}
        """)

def modify_argument(arg, default_value, new_value, isBPF=False):
	if arg == None:
		arg = default_value
	else:
		if isBPF:
			arg = ' '.join(new_value).strip()
		else:
			arg = new_value[0]
	return arg

def main():
	banner()
	args = Args() # Creating an object of ArgParser
	parser = args.parse()

	count = modify_argument(parser.count, 0, parser.count)
	outfile = modify_argument(parser.outfile, '', parser.outfile)
	bpf = modify_argument(parser.filter, 'port 80 and tcp', parser.filter, True)
	interface = modify_argument(parser.interface, None, parser.interface)
	isHTTP = parser.http_only

	sniff = SNIFF(
		count=count,
		passed_filters=bpf,
		outfile=outfile,
		iface=interface,
		isHTTP=isHTTP
		)
	sniff.run()

if __name__ == '__main__':
	main()
