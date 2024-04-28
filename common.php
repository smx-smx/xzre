<?php
/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/

use FFI\CData;

define('CHACHA20_KEY_SIZE', 32);
define('CHACHA20_IV_SIZE', 16);
define('SHA256_DIGEST_SIZE', 32);
define('ED448_KEY_SIZE', 57);

define('OP_ENCRYPT', 0);
define('OP_DECRYPT', 1);

function path_combine(string ...$parts){
    return implode(DIRECTORY_SEPARATOR, $parts);
}

function patch_data(string $data, int $offset, string $patch){
    return (''
        . substr($data, 0, $offset)
        . $patch
        . substr($data, $offset + strlen($patch))
    );
}

function error(string $msg){
    print("ERROR: {$msg}\n");
}

function say(string $msg){
    if(empty($msg)) print("\n");
    else print("[+] {$msg}\n");
}

function secret_data_crypto(string $data, int $op){
    $zero_data = str_repeat("\x00", CHACHA20_KEY_SIZE + CHACHA20_IV_SIZE);
    $zero_key = str_repeat("\x00", CHACHA20_KEY_SIZE);
    $zero_iv = str_repeat("\x00", CHACHA20_IV_SIZE);
    // get actual key,iv by decrypting zeros
    $decrypted = openssl_decrypt($zero_data, 'chacha20', $zero_key, OPENSSL_RAW_DATA, $zero_iv);

    $key = substr($decrypted, 0, CHACHA20_KEY_SIZE);
    $iv = substr($decrypted, CHACHA20_KEY_SIZE, CHACHA20_IV_SIZE);
    return ($op == OP_ENCRYPT)
        ? openssl_encrypt($data, 'chacha20', $key, OPENSSL_RAW_DATA, $iv)
        : openssl_decrypt($data, 'chacha20', $key, OPENSSL_RAW_DATA, $iv);
}

function encode_data(int $size, int $data){
    switch($size){
        case 1: return pack('C', $data);
        case 2: return pack('v', $data);
        case 4: return pack('V', $data);
        case 8: return pack('P', $data);
        default: throw new InvalidArgumentException("unsupported size {$size}");
    }
}

function make_bytearray(string $data, bool $owned = true){
    $arr = make_array(strlen($data), $owned);
    FFI::memcpy(FFI::addr($arr), $data, strlen($data));
    return $arr;
}

function make_array(int $size, bool $owned = true){
    $uchar = FFI::type('uint8_t');
    $arrT = FFI::arrayType($uchar, [$size]);
    return FFI::new($arrT, $owned);
}

function cdata_bytes(CData $object){
    $size = FFI::sizeof($object);
    return FFI::string(FFI::addr($object), $size);
}

function ptrval(CData $ptr){
	return FFI::cast('uintptr_t *', FFI::addr($ptr))[0];
}

function ptrdiff($a, $b){
	return $a - $b;
}

function ptradd($a, $b){
	return $a + $b;
}

function ffi_intval($a){
    if($a instanceof CData){
        return ptrval($a);
    }
    return $a;
}

function read8($a){ return FFI::cast('uint8_t *', $a)[0]; }
function read16($a){ return FFI::cast('uint16_t *', $a)[0]; }
function read32($a){ return FFI::cast('uint32_t *', $a)[0]; }
function read64($a){ return FFI::cast('uint64_t *', $a)[0]; }
function readptr($a){return  FFI::cast('uintptr_t *', $a)[0]; }

function write8($a, $v){ FFI::cast('uint8_t *', $a)[0] = ffi_intval($v); }
function write16($a, $v){ FFI::cast('uint16_t *', $a)[0] = ffi_intval($v); }
function write32($a, $v){ FFI::cast('uint32_t *', $a)[0] = ffi_intval($v); }
function write64($a, $v){ FFI::cast('uint64_t *', $a)[0] = ffi_intval($v); }
function writeptr($a, $v){ FFI::cast('uintptr_t *', $a)[0] = ffi_intval($v); }

function align_up(int $v, int $to){
	$mask = $to - 1;
	return ($v + $mask) & ~$mask;
}

function align_down(int $v, int $to){
	$mask = $to - 1;
	return $v & ~$mask;
}

function run_cmd(string ...$args){
    $hProc = proc_open($args, [], $p);
    return proc_close($hProc);
}

function der2pem($der_data, $type='CERTIFICATE') {
    $pem = chunk_split(base64_encode($der_data), 64, "\n");
    $pem = "-----BEGIN ".$type."-----\n".$pem."-----END ".$type."-----\n";
    return $pem;
}
