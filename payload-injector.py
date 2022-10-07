#!/usr/bin/env python3

import socket
import logging
import traceback
import argparse
import ipcalc

from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent
from termcolor import colored as _


ua = UserAgent().chrome
#########################################################################################

DPORT = 80                                  # Default port to scan 80 or 443
HOST = 'd3rmmgxjl3z51l.cloudfront.net'      # HOST for payload injection, e.g www.twitter.com, www.facebook.com

PAYLOAD = '''GET / HTTP/1.1
Host: {HOST}
Connection: Upgrade
Upgrade: websocket
User-Agent: {ua}

''' # the above empty line is required.
#########################################################################################

BUFFER_SIZE = 4096              # Default buffer size, no need to be changed!
TIMEOUT = 5                     # Default TCP connection timeout, the socket will be closed after the timeout.
MAX_THREADS = 1000              # Parallel connections at the same time 4000 is a nice.
verbose = False
PROXY = None 					# Proxy e.g: 55.214.25.3:80

#########################################################################################

# Configuring a logging system
fmt = "%(asctime)s - [%(levelname)s]: %(message)s"
logging.basicConfig(level=logging.DEBUG, format=fmt)
logger = logging.getLogger(__file__)


ipranges = {"CLOUDFRONT_GLOBAL_IP_LIST": ["120.52.22.96/27", "205.251.249.0/24", "180.163.57.128/26", "204.246.168.0/22", "18.160.0.0/15", "205.251.252.0/23", "54.192.0.0/16", "204.246.173.0/24",
										  "54.230.200.0/21", "120.253.240.192/26", "116.129.226.128/26", "130.176.0.0/17", "108.156.0.0/14", "99.86.0.0/16", "205.251.200.0/21", "223.71.71.128/25", "13.32.0.0/15", "120.253.245.128/26", "13.224.0.0/14", "70.132.0.0/18",
										  "15.158.0.0/16", "13.249.0.0/16", "18.238.0.0/15", "18.244.0.0/15", "205.251.208.0/20", "65.9.128.0/18", "130.176.128.0/18", "58.254.138.0/25", "54.230.208.0/20", "116.129.226.0/25", "52.222.128.0/17", "18.164.0.0/15", "64.252.128.0/18",
										  "205.251.254.0/24", "54.230.224.0/19", "71.152.0.0/17", "216.137.32.0/19", "204.246.172.0/24", "18.172.0.0/15", "120.52.39.128/27", "118.193.97.64/26",
										  "223.71.71.96/27", "18.154.0.0/15", "54.240.128.0/18", "205.251.250.0/23", "180.163.57.0/25", "52.46.0.0/18", "223.71.11.0/27", "52.82.128.0/19", "54.230.0.0/17", "54.230.128.0/18", "54.239.128.0/18", "130.176.224.0/20", "36.103.232.128/26", "52.84.0.0/15", "143.204.0.0/16", "144.220.0.0/16", "120.52.153.192/26", "119.147.182.0/25", "120.232.236.0/25", "54.182.0.0/16", "58.254.138.128/26",
										  "120.253.245.192/27", "54.239.192.0/19", "18.64.0.0/14", "120.52.12.64/26", "99.84.0.0/16", "130.176.192.0/19", "52.124.128.0/17", "204.246.164.0/22", "13.35.0.0/16", "204.246.174.0/23", "36.103.232.0/25", "119.147.182.128/26", "118.193.97.128/25", "120.232.236.128/26", "204.246.176.0/20", "65.8.0.0/16", "65.9.0.0/17", "108.138.0.0/15", "120.253.241.160/27", "64.252.64.0/18"],
			"CLOUDFRONT_REGIONAL_EDGE_IP_LIST": ["13.113.196.64/26", "13.113.203.0/24", "52.199.127.192/26", "13.124.199.0/24", "3.35.130.128/25", "52.78.247.128/26", "13.233.177.192/26", "15.207.13.128/25", "15.207.213.128/25", "52.66.194.128/26", "13.228.69.0/24", "52.220.191.0/26", "13.210.67.128/26", "13.54.63.128/26", "99.79.169.0/24", "18.192.142.0/23", "35.158.136.0/24", "52.57.254.0/24", "13.48.32.0/24", "18.200.212.0/23", "52.212.248.0/26", "3.10.17.128/25", "3.11.53.0/24", "52.56.127.0/25", "15.188.184.0/24", "52.47.139.0/24", "18.229.220.192/26", "54.233.255.128/26", "3.231.2.0/25", "3.234.232.224/27", "3.236.169.192/26", "3.236.48.0/23", "34.195.252.0/24", "34.226.14.0/24", "13.59.250.0/26", "18.216.170.128/25", "3.128.93.0/24", "3.134.215.0/24", "52.15.127.128/26", "3.101.158.0/23", "52.52.191.128/26", "34.216.51.0/25", "34.223.12.224/27", "34.223.80.192/26", "35.162.63.192/26", "35.167.191.128/26", "44.227.178.0/24", "44.234.108.128/25", "44.234.90.252/30"]}


cloudfront_global_list = ipranges["CLOUDFRONT_GLOBAL_IP_LIST"]
cloudfront_regional_list = ipranges["CLOUDFRONT_REGIONAL_EDGE_IP_LIST"]


def ip_generator(iprange_list):
	'''Parse IPs from list of ipranges'''
	for iprange in iprange_list:
		for ip in ipcalc.Network(iprange):
			yield ip


def get_headers(data):
	data = data.decode().split('\r\n\r\n')
	return data[0]


def parse_headers(data):
	return get_headers(data).split('\r\n')


def check(ip, port):
	if verbose:
		logger.debug(_(f'{ip}:{DPORT} - Checking...', 'cyan'))

	try:
		# Using a TCP socket
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
			conn.settimeout(TIMEOUT)
			conn.connect((ip, port))

			if verbose:
				logger.debug(_(f'{ip}:{DPORT} - Connected.', 'white'))
				logger.debug(f'{ip}:{DPORT} - Injecting payload...')
			# Send/inject a Payload
			conn.sendall(PAYLOAD.encode())

			if verbose:
				logger.debug(f'{ip}:{DPORT} - Waiting for reply...')
			# Waiting for receiving data
			data = conn.recv(BUFFER_SIZE)

			logger.debug(_(f'{ip}:{DPORT} - {len(data)} Bytes received.', 'magenta'))
			logger.debug(_(f"{ip}:{DPORT} - {get_headers(data)}", 'blue'))

			status_code = int(parse_headers(data)[0].split(' ')[1])

			if status_code == 101:
				logger.info(_(f'{ip}:{DPORT} - STATUS_CODE: {status_code}', 'green'))
			elif 200 <= status_code < 300:
				logger.info(_(f'{ip}:{DPORT} - STATUS_CODE: {status_code}', 'magenta'))
			# else:
			#     logger.debug(_(f"STATUS_CODE: {status_code}", 'magenta'))

	except (OSError, socket.timeout) as e:
		if verbose:
			logger.warning(_(f'{ip}:{DPORT} - {e}', 'yellow'))
	# if verbose:
	#     logger.info(_(f'{ip}:{DPORT} - Closed.', 'cyan'))


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Scanning and Injecting payload, powred by MadMax.')
	parser.add_argument('--host', help='The HOST that will be used with the payload.')
	parser.add_argument('--port', type=int, default=80, help='A TCP port to connect to, (default 80), (e.g. 80, 443).')
	parser.add_argument('--iprange', action='append', help='An IP range to scan and inject with payload (if not set, cloudfront ip ranges will be used), e.g. 55.25.32.0/24 or 68.156.8.0/16')
	parser.add_argument('--verbose', action='store_true', help='Show debug/all messages output.')
	parser.add_argument('--workers', type=int, default=MAX_THREADS, help=f'Maximum concurrent TCP connections (default {MAX_THREADS})')
	parser.add_argument('--timeout', type=int, default=TIMEOUT, help=f'A timeout before closing the TCP socket, (default {TIMEOUT}s)')
	parser.add_argument('--proxy', help='Proxy e.g: 55.214.25.3:80')

	args = parser.parse_args()

	# Override default variables
	if args.iprange:
		iprange_list = args.iprange
	else:
		iprange_list = cloudfront_global_list + cloudfront_regional_list

	DPORT = int(args.port) if args.port else DPORT
	HOST = args.host if args.host else HOST
	verbose = args.verbose
	PAYLOAD = PAYLOAD.format(**{'HOST': HOST, 'ua': ua})
	MAX_THREADS = int(args.workers) if args.workers else MAX_THREADS
	TIMEOUT = int(args.timeout) if args.timeout else TIMEOUT
	PROXY = args.proxy if args.proxy else PROXY

	futures = {}
	logger.info(_(f'''
############# Used Payload #############
{PAYLOAD}########################################''', 'cyan'))

	if PROXY:
		logger.info(_(f'Start connecting via proxy ({PROXY}) and injecting payload...', 'cyan'))
	else:
		logger.info(_(f'Start scanning and injecting payload on TCP port {DPORT} ...', 'cyan'))

	try:
		# Create a thread pool to handle requests
		MAX_THREADS = 5 if PROXY else MAX_THREADS
		ex = ThreadPoolExecutor(max_workers=MAX_THREADS)

		# Use proxy
		if PROXY is not None and ':' in PROXY:
			proxy, port = str(PROXY).split(':')
			port = int(port)
			futures[ex.submit(check, proxy, port)] = proxy
		else:
			# Use Cloudfront ip ranges.
			for ip in ip_generator(iprange_list):
				ip = str(ip) # required str casting
				futures[ex.submit(check, ip, DPORT)] = ip

		for future in as_completed(futures):
			ip = futures[future]
			try:
				future.result()
			except Exception:
				logger.warning(_(f'{ip}:{DPORT} - exception occurred!', 'yellow'))
				logger.warning(_(f'{ip}:{DPORT} - {traceback.format_exc()}', 'yellow'))
	except KeyboardInterrupt:
		logger.info(_('Stopping...', 'cyan'))
		ex.shutdown(False)
		# Cancel all the futures
		for f, _ in futures.items():
			f.cancel()
	finally:
		logger.info('Finished.')

