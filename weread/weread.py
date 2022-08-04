import requests
import execjs
import time
import random
import base64


headers = {
    'Accept': 'application/json, text/plain, */*',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en,zh-CN;q=0.9,zh;q=0.8',
    'Connection': 'keep-alive',
    'Content-Length': '173',
    'Content-Type': 'application/json;charset=UTF-8',
    'Host': 'weread.qq.com',
    'Origin': 'https://weread.qq.com',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36',
}


def decode(data: list):
    if len(data) == 4:
        del data[2]
    text = "".join([x[20:] for x in data])
    text = ctx.call('_0xc12ab5', text)
    return base64.b64decode(text).decode("utf-8", errors="ignore")



def main():

    book_id = "33362049"
    chapter_id = "15"
    cookie = "" # 登录 Cookie

    headers["Cookie"] = cookie
    # headers["referer"] = "https://weread.qq.com/web/reader/bd43298071fd1081bd4cb34"
    # 电子书有 e_0, e_1, e_2, e_3
    # 其中 t_1 是样式， t_0, t_1, t_3 是内容

    # 网文 t_0 , t_1， 都是内容

    psvts = pclts = ctx.call('_0x5a6265', int(time.time()))

    # 电子书
    docs = []
    for _url in ["e_0", "e_1", "e_2", "e_3"]:
        url = f"https://weread.qq.com/web/book/chapter/" + _url
        data = {
            "b": ctx.call("_0x5a6265", book_id),
            'c': ctx.call("_0x5a6265", chapter_id),
            'ct': int(time.time()),
            'pc': pclts,
            'ps': psvts,
            'r': random.randint(1, 10000) ** 2,
            'st': 0
        }
        data["s"] = ctx.call("_0x1ce365", "&".join([f"{k}={v}" for k, v in data.items()]))
        print(data)
        resp = requests.post(url, headers=headers, json=data)
        print(resp.text)
        docs.append(resp.text)

    text = decode(docs)
    print(text)



if __name__ == '__main__':
    ctx = execjs.compile(open("./weread.js", "r", encoding="utf-8").read())
    main() 


