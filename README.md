## ptdl
Script automates file downloading when plaintext directory listing was found.

## Options:
```
  --file	Mandatory - file containing valid HTTP request with "INJECT" mark point. Mark point specifies where enumerated filenames should be appended. (--file=/tmp/req.txt)

  --rhost	Remote host's IP address or domain name. Use this argument only for requests without Host header. (--rhost=192.168.0.3)
  --rport	Remote host's TCP port. Use this argument only for requests without Host header and for non-default values. (--rport=8080)

  --ssl		Use SSL.
  --proxy	Proxy to use. (--proxy=127.0.0.1:8080)

  --timeout	Timeout for receiving file/directory content. (--timeout=20)
  --fast	Skip asking what to enumerate. Prone to false-positives.
  --verbose	Show verbose messages.
```

## Example usage:
```
ruby ptdl.rb --file=/tmp/req.txt --ssl
```
