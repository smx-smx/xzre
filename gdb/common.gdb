source gdb/gdb_commands.py

define on_endless_loop
	library_bounds liblzma.so.5 lzma
	find_bytes post_setup, $lzma_start, $lzma_end, 4889D731C0F3AB498B4710488B4040498985A0
	b *$post_setup
	commands
		python post_setup()
		clear *$post_setup
		continue
	end

	# unblock endless loop
	set $pc += 2
	continue
end


define handle_liblzma
	echo ==== on_liblzma\n
	library_bounds liblzma.so.5 lzma
	find_bytes backdoor_entry, $lzma_start, $lzma_end, 554531C94889E55389FB4C8D45C04883
	find_bytes hook_RSA_public_decrypt, $lzma_start, $lzma_end, F30F1EFA4156415541544989F4554883
	find_bytes run_backdoor_commands, $lzma_start, $lzma_end, F30F1EFA4157B9AE00000031C0415641
	find_bytes verify_signature, $lzma_start, $lzma_end, 415741564155415455534881ECC80000004C8944
	find_bytes sshd_proxy_elevate, $lzma_start, $lzma_end, F30F1EFA550F57C0B93602000031C048
	find_bytes hook_RSA_get0_key, $lzma_start, $lzma_end, F30F1EFA41564154554889F54883EC20
	find_bytes is_payload_message, $lzma_start, $lzma_end, F30F1EFA4885FF0F843F0100004883FE

	hbreak *$hook_RSA_public_decrypt
	commands
		echo === hook_RSA_public_decrypt\n
		continue
	end
	echo === b verify_signature\n
	hbreak *$verify_signature
	commands
		echo === verify_signature\n
		printf "key type: %d\n", *(unsigned int *)$rdi
		python
import gdb
[gdb.execute(cmd) for cmd in ['finish', 'p $eax', 'continue']]
		end
	end

	info inferior
end