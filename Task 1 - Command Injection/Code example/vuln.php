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
        $cmd = $_POST["ip"];
        $result = shell_exec("timeout 10 ping -c 4 $cmd 2>&1");
        die(nl2br($result));
    } else {
        die("Please provide a valid IP address");
    }

?>
</body>
</html>