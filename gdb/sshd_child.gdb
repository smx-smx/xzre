set confirm off
set pagination off
set disassembly-flavor intel

source gdb/common.gdb

define on_child_endless_loop
	# on_endless_loop
	# handle_liblzma
	set $pc += 2
	continue
end

define setup_child_reexec_hook
	catch fork
	commands
		#python fork_capture_child_pid()
		python
fork_attach_child_pid()
wait_endless_loop('on_child_endless_loop', 'child', True)
		end
	end
end

define child_flow
	library_bounds liblzma.so.5 lzma
	find_bytes hook_RSA_get0_key, $lzma_start, $lzma_end, F30F1EFA41564154554889F54883EC20
	find_global_context $hook_RSA_get0_key global_ctx_loc
	set $global_ctx = *(void **)$global_ctx_loc
	catch load liblzma
	commands
		delete
		handle_liblzma
		continue
	end
	handle_liblzma
	# 
	handle SIGTERM noprint nostop nopass
end

set $child_mode = 0

python
import os
import gdb
pid = os.environ['GDB_TARGET']
print(f"pid: {pid}")
gdb.execute(f"attach {pid}")

opmode = os.environ.get('GDB_OPMODE')
if opmode == 'child':
	gdb.execute('set $child_mode = 1')
	gdb.execute('set follow-fork-mode child')
	#gdb.execute('child_flow')
else:
	write_pid('listener', gdb.inferiors()[0].pid)
	#gdb.execute('setup_child_reexec_hook')
end

if $child_mode == 1
	child_flow
end

continue
#quit
