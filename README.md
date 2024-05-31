## 微信sqlite解密

安装库

```bash
pip install -r requirements.txt
```

登录状态的微信获取key

```bash
python 1-search_wecaht_key.py
# OR
wechat-dump-rs.exe
```

复制MSG0.db到当前目录，通过key解密

```bash
python 2-decode_db.py
```

效果如图

![](1.jpg)

![](2.jpg)
