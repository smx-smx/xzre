#
# Author: Stefano Moioli <smxdev4@gmail.com>
#

import gdb
import re
import struct
import inspect
import subprocess
import os

class FindGlobalContextCommand(gdb.Command):
	def __init__(self) -> None:
		super().__init__('find_global_context', gdb.COMMAND_USER)

	def invoke(self, argument: str, from_tty: bool) -> None:
		[code_addr, var_name] = argument.split()
		result = gdb.execute(f'x/10i {code_addr}', to_string=True)
		[addr] = re.findall(f'# (0x[0-9a-f]+)', result)
		gdb.execute(f"set ${var_name} = {addr}")

class ForkFollowCommand(gdb.Command):
	def __init__(self) -> None:
		super().__init__('fork_follow', gdb.COMMAND_USER)

	def invoke(self, argument: str, from_tty: bool) -> None:
		[pid_var] = argument.split()
		result = gdb.execute('finish', to_string=True)
		[pid] = re.findall(r'\d+', result)
		print(f"now set {pid_var} to {pid}")
		gdb.execute(f"set ${pid_var} = {pid}")

class GetLibraryBoundsCommand(gdb.Command):
	def __init__(self) -> None:
		super(GetLibraryBoundsCommand, self).__init__('library_bounds', gdb.COMMAND_USER)
	
	def invoke(self, argument: str, from_tty: bool) -> None:
		args = argument.split()
		[lib_name, var_prefix] = args
		lib_start, lib_end = find_library(lib_name)
		gdb.execute(f"set ${var_prefix}_start = {lib_start}")
		gdb.execute(f"set ${var_prefix}_end = {lib_end}")

def split_hex_string(hex_string):
	hex_string = hex_string.lstrip("0x")
	# split the string into pairs of characters
	pairs = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
	formatted_string = ", ".join([f"0x{pair}" for pair in pairs])
	return formatted_string

def find_library(lib_name):
	result = gdb.execute(f'info sharedlib {lib_name}', to_string=True)
	[lib_start, lib_end] = re.findall(r'0x[0-9a-fA-F]+', result)
	return (lib_start, lib_end)

def find_bytes(start, end, pattern):
	hex_bytes = split_hex_string(pattern)
	find_output = gdb.execute("find/b {}, {}, {}".format(start, end, hex_bytes), to_string=True)
	[find_addr] = re.findall(r'0x[0-9a-fA-F]+', find_output)
	return find_addr

class FindBytesCommand(gdb.Command):
	def __init__(self) -> None:
		super(FindBytesCommand, self).__init__('find_bytes', gdb.COMMAND_USER)

	def invoke(self, argument: str, from_tty: bool) -> None:
		args = argument.split(', ')
		[var, start, end, pattern] = [args[0], args[1], args[2], args[3]]
		start = gdb.parse_and_eval(start)
		end = gdb.parse_and_eval(end)
		find_addr = find_bytes(start, end, pattern)
		gdb.execute(f"set ${var} = {find_addr}")

GetLibraryBoundsCommand()
FindBytesCommand()
ForkFollowCommand()
FindGlobalContextCommand()

def find_global_context():
	(lzma_start, lzma_end) = find_library('liblzma.so.5')
	hook_RSA_get0_key = find_bytes(lzma_start, lzma_end, 'F30F1EFA41564154554889F54883EC20')
	result = gdb.execute(f'x/10i {hook_RSA_get0_key}', to_string=True)
	[addr] = re.findall(f'# (0x[0-9a-f]+)', result)
	return addr

def get_base(exe: str, pid: int):
	out = subprocess.check_output(f"grep -E 'r--p 00000000.*{exe}' /proc/{pid}/maps | cut -d '-' -f1", shell=True)
	return int(out.decode('utf-8').rstrip(), 16)

def write_pid(name:str, pid:int):
	with open(f'gdb/pid_{name}', 'w') as f:
		f.write(str(pid))

def wait_endless_loop(on_endless_loop:str, name:str = 'main', forced:bool = False):
	wait_loop = os.environ.get('GDB_WAIT_LOOP')
	if not forced and (wait_loop is None or int(wait_loop) == 0):
		gdb.execute('continue')
		return

	pid = gdb.inferiors()[0].pid
	while True:
		dasm = gdb.execute('x/i $pc', to_string=True)
		print(dasm)
		addrs = re.findall(r'0x[0-9a-fA-F]+', dasm)
		is_endless_loop = (len(addrs) == 2\
			and 'jmp' in dasm\
			and addrs[0] == addrs[1])

		if is_endless_loop:
			if len(on_endless_loop) > 0:
				gdb.execute(on_endless_loop)
			break
		else:
			write_pid(name, pid)
			gdb.execute('continue')

def fork_capture_child_pid():
	gdb.execute('finish')
	pid = gdb.parse_and_eval('$rax')
	print(f'child: {pid}')
	write_pid('child', int(pid))

def fork_attach_child_pid():
	gdb.execute('finish')
	pid = gdb.parse_and_eval('$rax')
	print(f'-- attaching to {pid}')
	gdb.execute(f'attach {pid}')
	gdb.execute('x/i $pc')


def post_setup():
	print('-- post_setup')
	tgt = gdb.inferiors()[0]

	global_ctx_ptr_loc = int(find_global_context(), 16)
	global_ctx_ptr = struct.unpack('<Q', tgt.read_memory(global_ctx_ptr_loc, 8))[0]

	fmt_ctx = '<QQQQQQQQQQLLQQQQQQQQQ64sQQQQLL57s31sQ'
	ctx_data = struct.unpack(fmt_ctx,
		tgt.read_memory(global_ctx_ptr, struct.calcsize(fmt_ctx)))

	sshd_base = get_base('/usr/sbin/sshd', tgt.pid)
	lzma_base = get_base('liblzma.so.5', tgt.pid)

	print(inspect.cleandoc(f'''
	- uses_endbr64: {hex(ctx_data[0])}
	- imported_funcs: {hex(ctx_data[1])}
	- libc_imports: {hex(ctx_data[2])}
	- disable_backdoor: {ctx_data[3]}
	- sshd_ctx: {hex(ctx_data[4])}
	- sshd_sensitive_data: {hex(ctx_data[5])}, r {hex(ctx_data[5] - sshd_base)}
	- sshd_log_ctx: {hex(ctx_data[6])}
	- STR_ssh_rsa_cert_v01_openssh_com: {hex(ctx_data[7])}, r {hex(ctx_data[7] - sshd_base)}
	- STR_rsa_sha2_256: {hex(ctx_data[8])}, r {hex(ctx_data[8] - sshd_base)}
	- struct_monitor_ptr_address: {hex(ctx_data[9])}, r {hex(ctx_data[9] - sshd_base)}
	- exit_flag: {hex(ctx_data[10])}
	- sshd_offsets: {hex(ctx_data[11])}
	- sshd_code_start: {hex(ctx_data[12])}, r {hex(ctx_data[12] - sshd_base)}
	- sshd_code_end: {hex(ctx_data[13])}, r {hex(ctx_data[13] - sshd_base)}
	- sshd_data_start: {hex(ctx_data[14])}, r {hex(ctx_data[14] - sshd_base)}
	- sshd_data_end: {hex(ctx_data[15])}, r {hex(ctx_data[15] - sshd_base)}
	- sshd_main: {hex(ctx_data[16])}, r {hex(ctx_data[16] - sshd_base)}
	- lzma_code_start: {hex(ctx_data[17])}
	- lzma_code_end: {hex(ctx_data[18])}
	- uid: {hex(ctx_data[19])}
	- sock_read_buf_size: {hex(ctx_data[20])}
	- sock_read_buf: {ctx_data[21].hex()}
	- payload_data_size: {hex(ctx_data[22])}
	- digest_offset: {hex(ctx_data[23])}
	- payload_data: {hex(ctx_data[24])}
	- sshd_payload_ctx: {hex(ctx_data[25])}
	- sshd_host_pubkey_idx: {hex(ctx_data[26])}
	- payload_state: {hex(ctx_data[27])}
	- secret_data: {ctx_data[28].hex()}
	- shift_operations: {ctx_data[29].hex()}
	- num_shifted_bits: {hex(ctx_data[30])}
	------------------------------------------------
	'''))

	payload_data = tgt.read_memory(ctx_data[24], ctx_data[22])
	print(f'- payload_data: {payload_data.hex()}')

	fmt_sshd_ctx = '<LLLLQQQQQQQQQQQQQQLHHQQQQQQLLQQQQ'
	sshd_ctx = struct.unpack(fmt_sshd_ctx, tgt.read_memory(ctx_data[4], struct.calcsize(fmt_sshd_ctx)))

	print(inspect.cleandoc(f'''
	- have_mm_answer_keyallowed: {hex(sshd_ctx[0])}
	- have_mm_answer_authpassword: {hex(sshd_ctx[1])}
	- have_mm_answer_keyverify: {hex(sshd_ctx[2])}
	- have_unk: {hex(sshd_ctx[3])}
	- monitor_req_fn: {hex(sshd_ctx[4])}
	- unk: {hex(sshd_ctx[5])}
	- unk: {hex(sshd_ctx[6])}
	- mm_answer_authpassword_start: {hex(sshd_ctx[7])} r {hex(sshd_ctx[7] - sshd_base)}
	- mm_answer_authpassword_end: {hex(sshd_ctx[8])} r {hex(sshd_ctx[8] - sshd_base)}
	- mm_answer_authpassword_ptr: {hex(sshd_ctx[9])} r {hex(sshd_ctx[9] - sshd_base)}
	- unk: {hex(sshd_ctx[10])}
	- mm_answer_keyallowed_start: {hex(sshd_ctx[11])} r {hex(sshd_ctx[11] - sshd_base)}
	- mm_answer_keyallowed_end: {hex(sshd_ctx[12])} r {hex(sshd_ctx[12] - sshd_base)}
	- mm_answer_keyallowed_ptr: {hex(sshd_ctx[13])} r {hex(sshd_ctx[13] - sshd_base)}
	- unk: {hex(sshd_ctx[14])}
	- mm_answer_keyverify_start: {hex(sshd_ctx[15])} r {hex(sshd_ctx[15] - sshd_base)}
	- mm_answer_keyverify_end: {hex(sshd_ctx[16])} r {hex(sshd_ctx[16] - sshd_base)}
	- mm_answer_keyverify_ptr: {hex(sshd_ctx[17])} r {hex(sshd_ctx[17] - sshd_base)}
	- unk: {hex(sshd_ctx[18])}
	- writebuf_size: {hex(sshd_ctx[19])}
	- unk: {hex(sshd_ctx[20])}
	- writebuf: {hex(sshd_ctx[21])}
	- unk: {hex(sshd_ctx[22])}
	- unk: {hex(sshd_ctx[23])}
	- unk: {hex(sshd_ctx[24])} r {hex(sshd_ctx[24] - sshd_base)}
	- mm_request_send_start: {hex(sshd_ctx[25])} r {hex(sshd_ctx[25] - sshd_base)}
	- mm_request_send_end: {hex(sshd_ctx[26])} r {hex(sshd_ctx[26] - sshd_base)}
	- unk: {hex(sshd_ctx[27])}
	- unk: {hex(sshd_ctx[28])}
	- use_pam_ptr: {hex(sshd_ctx[29])} r {hex(sshd_ctx[29] - sshd_base)}
	- permit_root_login_ptr: {hex(sshd_ctx[30])} r {hex(sshd_ctx[30] - sshd_base)}
	- STR_without_password: {hex(sshd_ctx[31])} r {hex(sshd_ctx[31] - sshd_base)}
	- STR_publickey: {hex(sshd_ctx[32])} r {hex(sshd_ctx[32] - sshd_base)}
	------------------------------------------------
	'''))
	
