<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Endpoint Check</title>
</head>
<body>
    <h1>Endpoint Check</h1>
    <form method="post" enctype="multipart/form-data">
        <label for="url">URL:</label>
        <input type="text" id="url" name="url" required><br><br>

        <label for="hash">Hash:</label>
        <input type="text" id="hash" name="hash"><br><br>

        <label for="file">File:</label>
        <input type="file" id="file" name="file"><br><br>

        <label for="hash_alg">Hash Algorithm:</label>
        <input type="text" id="hash_alg" name="hash_alg" value="md5"><br><br>

        <label for="debug">Debug:</label>
        <input type="checkbox" id="debug" name="debug"><br><br>

        <input type="submit" value="Check">
    </form>

    <?php
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        function getIps($hostname) {
            $result = dns_get_record($hostname, DNS_A);
            $ips = [];
            foreach ($result as $record) {
                if (isset($record['ip'])) {
                    $ips[] = $record['ip'];
                }
            }
            return $ips;
        }

        function downloadContent($url, $hostname, $ip, $protocol, $debug) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_RESOLVE, ["$hostname:$protocol:$ip"]);
            $content = curl_exec($ch);
            curl_close($ch);

            if ($debug) {
                echo "Downloaded content from $url to $ip directory<br>";
            }

            return $content;
        }

        function computeHash($content, $hashAlg) {
            return hash($hashAlg, $content);
        }

        $url = $_POST['url'] ?? null;
        $hash = $_POST['hash'] ?? null;
        $file = $_FILES['file']['tmp_name'] ?? null;
        $hashAlg = $_POST['hash_alg'] ?? 'md5';
        $debug = isset($_POST['debug']);

        if (!$url) {
            echo "URL is required.<br>";
            exit(1);
        }

        if ($file) {
            if (file_exists($file)) {
                $hash = hash_file($hashAlg, $file);
            } else {
                echo "File does not exist.<br>";
                exit(1);
            }
        }

        $protocol = (strpos($url, 'https://') === 0) ? 443 : 80;
        $hostname = parse_url($url, PHP_URL_HOST);
        $ips = getIps($hostname);

        if ($debug) {
            echo "URL: $url<br>";
            echo "HASH: $hash<br>";
            echo "PROTOCOL: $protocol<br>";
            echo "HOSTNAME: $hostname<br>";
            echo "HASH_ALG: $hashAlg<br>";
            echo "IPS: " . implode(', ', $ips) . "<br>";
        }

        foreach ($ips as $ip) {
            $content = downloadContent($url, $hostname, $ip, $protocol, $debug);
            $computedHash = computeHash($content, $hashAlg);

            if ($hash) {
                if ($computedHash === $hash) {
                    echo "Hash matches || $ip<br>";
                } else {
                    echo "Hash <span style='color:red;'>NOT</span> matches || $ip<br>";
                }
            } else {
                echo "$hashAlg hash: $computedHash<br>";
            }
        }
    }
    ?>
</body>
</html>