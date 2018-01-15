<?php
//获取url传递过来的参数
parse_str($_SERVER['QUERY_STRING'], $parseUrl);
//需要多少参数用户可自己顶
if( !array_key_exists('token', $parseUrl) ){
    //拒绝
    echo "Auth:0";
    exit;
}

$db = new mysqli('localhost', 'root', '', 'test');
$db->query("set names 'utf8'");
$token = $parseUrl['token'];
$sql = "SELECT * FROM user WHERE token='{$token}'";
$result = $db->query($sql);
if($result && $result->num_rows != 0){
    //token匹配，验证通过
    echo "Auth:1";
}else{
    echo "Auth:0";
}


