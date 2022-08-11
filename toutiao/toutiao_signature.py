import requests
import execjs
import time


headers = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'accept-language': 'zh-CN,zh;q=0.9',
    'sec-ch-ua': '"Chromium";v="104", " Not A;Brand";v="99", "Microsoft Edge";v="104"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36 Edg/104.0.1293.47',
}


ctx = execjs.compile(open("./toutiao_signature.js", "r", encoding="utf-8").read())


def main():
    base_url = f"https://www.toutiao.com/api/pc/list/feed?channel_id=0&max_behot_time={int(time.time())}&category=pc_profile_recommend&aid=24&app_name=toutiao_web"
    _signature = ctx.call("get_sgin", base_url)
    # print(_signature)
    url = base_url + "&_signature=" + _signature
    print(url)
    resp = requests.get(url, headers=headers).json()
    print(resp)
    


if __name__ == "__main__":
    main()
