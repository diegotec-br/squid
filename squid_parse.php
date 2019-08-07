#!/usr/bin/php


<?php

$db_host = 'ip_dns';
$db_name = 'squid';
$db_user = 'usuario'; // Usuário precisa ter permissão de escrita na base.
$db_pass = 'senha';
$squid_log = '/var/log/squid/access.log';

$conn = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8", $db_user, $db_pass);

$handle = popen("tail -f $squid_log 2>&1", 'r');

while(!feof($handle)) {
    $buffer = fgets($handle);
    $log_line = preg_replace('/[ ]+/',',',$buffer);

    $array_line = explode('\n',$log_line);

    $log = explode(',',$log_line);

    $log['time'] = $log[0];
    $log['elapsed'] = $log[1];
    $log['remotehost'] = $log[2];
    //$log['code_status'] = $log[3];
    $code_status = explode('/',$log[3]);
    if ($code_status[0] == 'TCP_DENIED') continue; // Ignora acessos NEGADOS
    $log['status'] = $code_status[0];
    $log['code'] = $code_status[1];
    $log['bytes'] = $log[4];
    $log['method'] = $log[5];
    $log['url'] = $log[6];
    $log['user'] = $log[7];
    if ($log['user'] == '-') continue; // Ignora acessos em whitelist (Ou seja, sem usário autenticado)
    $log['peerstatus_peerhost'] = $log[8];
    $log['type'] = $log[9];

    $sql = 'INSERT INTO accesslog (time,remotehost,status,code,bytes,method,url,user) VALUES (:time,:remotehost,:status,:code,:bytes,:method,:url,:user)';

    $stmt = $conn->prepare($sql);
    $stmt->execute(array(
            ':time' => $log['time'],
            ':remotehost' => $log['remotehost'],
            ':status' => $log['status'],
            ':code' => $log['code'],
            ':bytes' => $log['bytes'],
            ':method' => $log['method'],
            ':url' => $log['url'],
            ':user' => $log['user']
        )
    );

    flush();
}
pclose($handle);
