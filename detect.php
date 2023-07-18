<?php
//usage: php detect.php
function scanning_by_extension($path) {
    //mencari file berdasar extensi yang berpotensi backdoor 
    exec("find $path -regex '.*\\(php\\|php3\\|php5\\|PhP\\|PhP3\\|PhP5\\|pHp\\|pHp3\\|pHp5\\|PHp\\|pHP\\|PHP\\|phps\\|PHPs\\|phtml\\|shtml\\|py\\|exe\\|pl\\|sh\\|rb\\|asp\\|aspx\\|c\\|js\\|jsp\\|jspx\\|cgi\\)$'", $output);
    file_put_contents('ress-extension.txt', implode("\n", $output));
    echo "Hasil nya => ress-extension.txt\n";
}

function scanning_by_function($path) {
    //referensi php function dangerous :
//https://gist.github.com/mccabe615/b0907514d34b2de088c4996933ea1720
//https://github.com/Cvar1984/sussyfinder/blob/main/main.php#L429
    $functions = array("eval", 
                      "system", 
                      "exec", 
                      "shell_exec", 
                      "passthru", 
                      "shell", 
                      "pcntl_fork", 
                      "fsockopen", 
                      "proc_open", 
                      "popen", 
                      "assert", 
                      "posix_kill", 
                      "posix_setpgid", 
                      "posix_setsid", 
                      "posix_setuid", 
                      "proc_nice", 
                      "proc_close", 
                      "proc_terminate", 
                      "apache_child_terminate", 
                      "posix_getuid", 
                      "posix_geteuid", 
                      "posix_getegid", 
                      "posix_getpwuid", 
                      "posix_getgrgid", 
                      "posix_mkfifo", 
                      "posix_getlogin", 
                      "posix_ttyname", 
                      "getenv", 
                      "proc_get_status", 
                      "get_cfg_var", 
                      "disk_free_space", 
                      "disk_total_space", 
                      "diskfreespace", 
                      "getlastmo", 
                      "getmyinode", 
                      "getmypid", 
                      "getmyuid", 
                      "getmygid", 
                      "fileowner", 
                      "phpinfo", 
                      "pathinfo", 
                      "filegroup", 
                      "getcwd", 
                      "get_current_user", 
                      "sys_get_temp_dir", 
                      "basename", 
                      "symlink", 
                      "session_start", 
                      "error_reporting", 
                      "create_function", 
                      "get_magic_quotes_gpc", 
                      "set_time_limit", 
                      "ini_set", 
                      "allow_url_fopen", 
                      "tmpfile", 
                      "curl_init", 
                      "putenv", 
                      "mail", 
                      "require", 
                      "reuire_once", 
                      "include", 
                      "include_once", 
                      "copy", 
                      "file_put_contents", 
                      "file_get_contents", 
                      "url_get_contents", 
                      "stream_get_meta_data", 
                      "move_uploaded_file", 
                      "fsockopen", 
                      "fopen", 
                      "base64_encode", 
                      "base64_decode", 
                      "gzinflate", 
                      "str_rot13", 
                      "convert_uu", 
                      "fwrite", 
                      "rawurldecode", 
                      "urldecode", 
                      "gzuncompress", 
                      "htmlspecialchars_decode", 
                      "bin2hex", 
                      "hex2bin", 
                      "hexdec", 
                      "chr", 
                      "strrev", 
                      "implode", 
                      "strtr", 
                      "extract", 
                      "parse_str", 
                      "substr", 
                      "mb_substr", 
                      "str_replace", 
                      "substr_replace", 
                      "preg_replace", 
                      "escapeshellcmd", 
                      "escapeshellarg", 
                      "php_uname", 
                      "phpversion", 
                      "chmod", 
                      "chown", 
                      "mkdir", 
                      "rmdir", 
                      "tempnam", 
                      "touch", 
                      "unlink");
    $result = array();

    foreach ($functions as $func) {
        exec("grep -rl \"$func\" $path", $output);
        foreach ($output as $file) {
            $result[] = "File: $file | Function: $func";
        }
    }

    file_put_contents('ress-function.txt', implode("\n", $result));
    echo "Hasil nya => ress-function.txt\n";
}
echo "#######################################\n";
echo "#          Backdoor detector          #\n";
echo "#             Author: Zaen            #\n";
echo "#######################################\n";
echo "Pilihan :\n";
echo "1. By Extension\n";
echo "2. By Function\n";
$option = readline("Pilih? ");

if ($option === "1") {
    $path = readline("Path file: ");
    if (empty($path)) {
        echo "Path kosong!\n";
        exit(1);
    }
    scanning_by_extension($path);
} elseif ($option === "2") {
    $path = readline("Path file: ");
    if (empty($path)) {
        echo "Path kosong!\n";
        exit(1);
    }
    scanning_by_function($path);
} else {
    echo "Invalid.\n";
    exit(1);
}
