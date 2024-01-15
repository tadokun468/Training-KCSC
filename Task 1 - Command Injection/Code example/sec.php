<html>
<head>
    <title>Task 01</title>
</head>
<body>
  <form method="POST">
      <input name="ip" type="text" placeholder="Enter your target IP">
      <input type="submit" value="Ping">
  </form>
  <?php
    if (isset($_POST["ip"])) {
        $whitelist = "/^[0-9.]+$/";
        if(!preg_match($whitelist,$_POST["ip"])){
            die('Please provide a valid IP address hahaha');
        }
        $targetIP = filter_input(INPUT_POST, 'ip', FILTER_VALIDATE_IP);
        if ($targetIP !== false && $targetIP !== null) {
            $cmd = escapeshellarg($targetIP);
            $result = shell_exec("timeout 10 ping -c 4 $cmd 2>&1");
            die(nl2br($result));
        } else {
            die("Please provide a valid IP address :( lol");
        }
    }
?>
</body>
</html>