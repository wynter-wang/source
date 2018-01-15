<?php
//获取url传递过来的参数
parse_str($_SERVER['QUERY_STRING'], $parseUrl);
//gw_address、gw_port、gw_id是必需参数，缺少不能认证成功.
if( !array_key_exists('gw_address', $parseUrl) || !array_key_exists('gw_port', $parseUrl) || !array_key_exists('gw_id', $parseUrl)){
    exit;
}
//如果提交了账号密码
if(isset($_POST['name']) && isset($_POST['password'])){
    $username = $_POST['name'];
    $password = $_POST['password'];
    $db = new mysqli('localhost', 'root', '', 'test');
    if(mysqli_connect_errno()){
        echo mysqli_connect_error();
        die;
    }
    $db->query("set names 'utf8'");
    $result = $db->query("SELECT * FROM user WHERE username='{$username}' AND password='{$password}'");
    if($result && $result->num_rows != 0){
        //数据库验证成功
        $token = '';
        $pattern="1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLOMNOPQRSTUVWXYZ";
        for($i=0;$i<32;$i++)
            $token .= $pattern[ rand(0,35) ];
        //把token放到数据库，用于后续验证（auth/index.php）
        $time = time();
        $sql = "UPDATE user SET token='{$token}',logintime='{$time}'";
        $db->query($sql);
        $db->close();
        //登陆成功，跳转到路由网管指定的页面.
        $url = "http://{$parseUrl['gw_address']}:{$parseUrl['gw_port']}/wifidog/auth?token={$token}";
        header("Location: ".$url);
    }else{
        //认证失败
        //直接重定向本页 请求变成get
        $url='http://'.$_SERVER['SERVER_NAME'].$_SERVER["REQUEST_URI"];
        header("Location: ".$url);
    }
}else{
    //get请求
    //一个简单的表单页面
    $html = <<< EOD
    <html>
        <head>
            <title>portal login</title>
        </head>
        <body>
            <form action="#" method="post">
            username:<input type="text" name="username" />
            password:<input type="password" name="password" />
            <input type="submit" value="submit" />
            </form>
        </body>
    </html>
EOD;
    echo $html;
}

