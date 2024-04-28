set confirm off
set pagination off
set breakpoint pending on
set startup-with-shell off
set disassembly-flavor intel

source gdb_commands.py
source common.gdb

define set_term
python
import os
os.environ['TERM'] = 'xterm-256color'
end
end

unset env
set env LANG=C
set env LD_LIBRARY_PATH=/tmp/xzre

file /usr/sbin/sshd
set args -f /tmp/sshd_config

define gdb_detach_p2
	python
pid = gdb.parse_and_eval('$rax')
with open('gdb/pid', 'w') as f:
	f.write(str(pid))
	end
	detach
	quit
end

define gdb_detach
	catch fork
	commands
		delete
		python
import gdb
[gdb.execute(cmd) for cmd in ['finish', 'gdb_detach_p2']]
		end
	end
end

python
import os
detach = os.environ.get('GDB_DETACH')
if detach is not None:
	gdb.execute('gdb_detach')

end



set_term
starti

python wait_endless_loop('on_endless_loop')

