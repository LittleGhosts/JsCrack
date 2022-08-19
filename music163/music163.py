import requests
import time
import execjs


headers = {
    'content-type': 'application/x-www-form-urlencoded',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36',
}


def main():
    ctx = execjs.compile(open("./music163.js", "r", encoding="utf-8").read())
    url = "https://music.163.com/weapi/comment/resource/comments/get?csrf_token="
    rid = "R_SO_4_1973067211"
    threadId = "R_SO_4_1973067211"
    pageNo = 3
    pageSize = 20
    cursor = int(time.time() * 1000)
    s = '{"rid":"%s","threadId":"%s","pageNo":"%s","pageSize":"%s","cursor":"%s","offset":"0","orderType":"1","csrf_token":""}' % (
        rid, threadId, pageNo, pageSize, cursor
    )
    data = ctx.call('get_seckey', s)
    print(s)
    print({'params': data["encText"], 'encSecKey': data["encSecKey"]})

    resp = requests.post(url, headers=headers, data={'params': data["encText"], 'encSecKey': data["encSecKey"]})
    print(resp.text)


main()
