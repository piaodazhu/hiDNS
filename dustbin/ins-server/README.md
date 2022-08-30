# ins-server: ICN Name System Server

## what is this

accept iNS query, then forward the query to local BIND9 server (for icn name) or other DNS server (for accessing existing domain name) or other modules according to mannul configure.

## architecture

- an ineffient multi-thread network server. (Will be redesign to IO multiplex server using epoll in the future.)

- 3 modules to support current DomainName resolving, ICN Name resolving and query forwarding.

- a fast prefix matching algorithm. (Maybe fast, need to be validated.)

- read configuration file to load global variables and routes.

- a Lite format for iNS packet. (It's like DNS packet, but not same.)

## prefix matching

Base on Robin Karp.

## configuration

Configure your INS server by editing `config.json`:
```json
{
    "GLOBAL": {
        "nickname": "whatever",
        "domainname": "whatever",
        "serveip": "0.0.0.0",
        "serveport": 5553,
        "authorizer": "Lab101"
    },
    "INS_PATH_LOCAL": {
        "prefix": [
            "/icn/prefix1/",
            "/icn/prefix2/"
        ],
        "resolver": "127.0.0.1",
        "dstport": 53
    },
    "INS_PATH_REMOTE": [
        {
            "prefix": [
                "/nip/"
            ],
            "resolver": "x.x.x.x",
            "dstport": 5553
        }
    ],
    "DNS_PATH": [
        {
            "prefix": [
                "/com/example/"
            ],
            "resolver": "127.0.0.1",
            "dstport": 53
        },
        {
            "prefix": [
                "/"
            ],
            "resolver": "114.114.114.114",
            "dstport": 53
        }
    ]
}
```

## packet format:

```
query {
    'transactionID': 2Byte,
    'query flags': 1Byte (recursion desired, unauth-acceptable, hoplimit, reserved)
    'min component number': 4bit (set this Byte to 0 if auto match),
    'max component number': 4bit (must less than 9),
    'query type': 1Byte (A, CNAME, TXT, IDA),
    'query name length': 1Byte (must less than 256),
    'query name': nByte (example: /edu/bit/lab101/news/2021/a-good-news),
}

answer {
    'transactionID': 2Byte,
    'answer flags': 4bit (recursion available, authenticated),
    'respond code': 4bit (no error, invalid component number, invalid name length, ...),
    'answer number': 4bit,
    'exact component number': 4bit,
    'exact prefix length': 1Byte,
    // 'exact prefix': nByte (example: /edu/bit/lab101/news/),
    [{   
        'answer TTL': 4Byte,
        'answer type': 1Byte,
        'answer length': 1Byte,
        'extension length' 2Byte,
        'answer value': nByte (IP address, TXT string, CNAME string)
    }]
}
```
## Q&A

### 1. why design new format instead of use DNS packet?

Name resolving is different from domain name resolving:

- DNS packet contain domain name, while iNS need lookup name's longest routable prefix. 
- A given name may have several routable prefix, so tell server about min/max components will greatly improve lookup effiency.
- iNS need not to support all query Class and TYPE, some fields can be omit.

