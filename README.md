# JSON WEB TOKEN

[TOC]

## 安装

```
composer require xudongyss/jwt
```
## 快速使用

### 生成 TOKEN

```php
require_once 'vendor/autoload.php';

use xudongyss\jwt\Token;

/* 私钥 */
$private = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCDVzoilq8VoHeslQIB9a5kpabkWj+9lJ89w1Yk2rw2JQjafGME6mJAGCHN+2XQrijNgzboeNWogvYLZmfRiP64JQGXJabU8XmkbOOCFihNV48HeJZSqns+yVZPeWJ3NXzDDr0cFd/tzaqLm2gN+3oI4M8RbLFdsDgkiRnLUTSvy3RTTmBWkscBKy/TrAZHSPvErLSu5X2TP05kzMVTRaZaLwoj3hPO5aJrKqHADrkUO56dwvf0N+vyZGwWT/KNyYbL1fycGBdNlFwePAQ+s4PiZdJqInHnr0r8BbMCagIZqGTqD5iykFfwoz0bB3ZUzGBSx1YKs7OEDJmzhSifU+sZAgMBAAECggEANtTTkF0X+w9i5snObMMEa0A8zFhhA+RoFoDWFcy7hl8vswb6z7KKEfgBJN0vRE9w+VsuMR9BE3iY/2lhLjjjHj1UzKULYRrujZZn5IcbjC5hp9zP5PMHQM8NGWCzmtDZpRUiHfeD5ONXr7DRYAT8jXhM+hlGcrZ+ucIC4r6kID9Porlr53lKaBcLsRvQjlzBB0WEQUtarhOAk7Dx4BOSfAKSlea6zE5vZe8p2y8fonk8uzDYwqmaKBmgfjDS9Jjvsd6WW/Hvj170NwlFT9PE9841LgILy0ltFdZkPBYDgXAsJ/GEHwMAfxcGLbjU4HNRsAxiRUlNbGQe4edCw0LOAQKBgQD45E/kBqA6+5Ge0kZaXSuRhv843gxSrTyUIeccql/nSZgHEDf+Bz/Qskvqy6Tpg4kTT0SeSRRNXprSkiCXzX1yRKo83GlCRR/xan4fYd9WY3LmabB0bfzhuSc+MyJpMi7mWirlT/TqvNsu7sm+2sIOdjEYjDYtpL/NoAWbKKNDlQKBgQCHF3rny0IGK5ysxleVXPc+yb4kn0x652ACDbyWPHVKvvOxtMv0Xd4mRByLvfxF+A/4GkStBdb/uLrZEaV2i8nLXp2/zMeTcuknug2Slofugqlxk4pM/rz2SuuvnyCtWCuE7G83knJpSlEjYwsXWjnBz7rlmaD6cPN3SQk9a9vodQKBgHdknmZWP1rL/wje+dyzQQkoZxoSenrWm2677K+1kxfSF9mbkCCNvbERNpXFZrCV5pWauuHrUI/kyAQnEPeBHaJJChjz6pJdsnsOiL3pJ0e7oQyiuoC/mkV1mjueL+2ioxjhPB6Qgn5wZfxXk/O34MsrK1YJPJwcod2z27yYe+kZAoGAdSmZD8WKCp3ycSpINaN+T7dasJp0EzfuXXmacNYYh+4anqoGJXbvv1JdS5lHXUuqVew6WbFx6TFG5BJY5fqQ1k/GEt3AzZHgwvKq6NKjK+momXdzgBmCuzz5McSZ651HiS4huxnJHqY0vrMcoHFBHGVUW+Mk6W/iyDbQy7Nq8y0CgYEA0jv2jh45wsz9TA5h23WC2pmD0ankVusv+9Jc92FhwgBYTcTH6acxJpTfoU3tv83Jpw6X1BLEiB0CxssnBioizNSQO+r/hTXPusyK0aHgnsxEkJNyw4cdopxWTOqTjchpbxowotTeFqUZvHbQCccNdaUhhwfEi2lIJoDikClXLB4=';
/* 公钥 */
$public = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg1c6IpavFaB3rJUCAfWuZKWm5Fo/vZSfPcNWJNq8NiUI2nxjBOpiQBghzftl0K4ozYM26HjVqIL2C2Zn0Yj+uCUBlyWm1PF5pGzjghYoTVePB3iWUqp7PslWT3lidzV8ww69HBXf7c2qi5toDft6CODPEWyxXbA4JIkZy1E0r8t0U05gVpLHASsv06wGR0j7xKy0ruV9kz9OZMzFU0WmWi8KI94TzuWiayqhwA65FDuencL39Dfr8mRsFk/yjcmGy9X8nBgXTZRcHjwEPrOD4mXSaiJx569K/AWzAmoCGahk6g+YspBX8KM9Gwd2VMxgUsdWCrOzhAyZs4Uon1PrGQIDAQAB';

/* 用户ID */
$uid = 100000001;
/* 扩展数据，可空 */
$extend = [];
$token = new Token($private, $public);
$token->create($uid, $extend);
```

### 校验

```php
/* Token */
$tokenString = '';
$token->validating($tokenString);
```

### 获取数据

```php
//jti
$token->getClaim('jti');
//uid
$token->getClaim('uid');
//extend
$token->getClaim('extend');
```

