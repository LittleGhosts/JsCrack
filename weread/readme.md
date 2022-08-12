# 微信阅读

## 请求

请求参数说明:

1. ```b```: ```BookId``` 加密
2. ```c```: ```chapterId``` 加密
3. ```r```: 整数 1 ~ 10000 的平方
4. ```st```: 0
5. ```ct```: 当前时间戳(秒)
6. ```psvts```: 时间戳加密
7. ```pclts```: 时间戳加密， 同上



## 解密

有两种类型，一种一个章节有四次请求，链接分别为:

出版书:
 + https://weread.qq.com/web/book/chapter/e_0
 + https://weread.qq.com/web/book/chapter/e_1
 + https://weread.qq.com/web/book/chapter/e_2
 + https://weread.qq.com/web/book/chapter/e_3

其中 e_2 返回的结果为 HTML style 样式，其他三个 ```e_0, e_1, e_3``` 为数据内容。

网文:
  + https://weread.qq.com/web/book/chapter/t_0
  + https://weread.qq.com/web/book/chapter/t_1

返回的数据均为内容


具体解密方法运行 wxread 即可

```cmd
(wk) D:\Github\Crack\weread>python wxread.py 
{'b': 'bd43298071fd1081bd4cb34', 'c': '9bf32f301f9bf31c7ff0a60', 'ct': 1659616576, 'pc': '88c3241079e45fb9g016c4e', 'ps': '88c3241079e45fb9g016c4e', 'r': 772641, 'st': 0, 's': 'b92e094b'}
019F6F053D32FD5DB20A05CD564FADEFPPD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiIHN0YW5kYWxvbmU9Im5vIj8+DQo8IURPQ1RZUEUgaHRtbCBQVUJMSUMgIi0vL1czQy8vRFREIFhIVE1MIDEuMS8vRU4iDQogICJodHRwOi8vd3d3LnczLm9yZy9UUi94aHRtbDExL0RURC94aHRtbDExLmR0ZCI+DQoNCjxodG1sIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hodG1sIj4NCjxoZWFkPg0KICA8dGl0bGU+PC90aXRsZT4NCiAgPGxpbmsgaHJlZj0iLi4vU3R5bGVzL3N0eWxlc2hlZXQuY3NzIiByZWw9InN0eWxlc2hlZXQiIHR5cGU9InRleHQvY3NzIiAvPg0KPC9oZWFkPg0KDQo8Ym9keT4NCiAgPGgyIGNsYXNzPSJzZWNvbmRUaXRsZSI+6YeR6J6N55qE5pys6LSoPC9oMj4NCg0KICA8cCBjbGFzcz0iY29udGVudCI+6YeR6J6N55qE5pys6LSo77yM5bCx5piv5LiJ5Y+l6K+d77ya5LiA5piv5Li65pyJ6ZKx5Lq655CG6LSi77yM5Li657y66ZKx5Lq66J6N6LWE77yb5LqM5piv6YeR6J6N5LyB5Lia55qE5qC45b+D6KaB5LmJ5bCx5Zyo5LqO5L+h55So44CB5p2g5p2G44CB6aOO6Zmp5LiJ5Liq546v6IqC77yM6KaB5oqK5o+h5aW95LiJ5Liq546v6IqC5ZKM5bqm77yb5LiJ5piv5LiA5YiH6YeR6J6N5rS75Yqo55qE55uu55qE5piv6KaB5Li65a6e5L2T57uP5rWO5pyN5Yqh44CC6L+Z5LiJ5Liq5pys6LSo54m55b6B77yM5LiN566h5piv5ZOq5Liq5bGC6Z2i55qE6YeR6J6N5LuO5Lia6ICF77yM6YO95bqU5pe25Yi76LCo6K6w5LqO5b+D44CCPC9wPg0KDQogIDxwIGNsYXNzPSJjb250ZW50Ij7nrKzkuIDvvIzkuLrmnInpkrHkurrnkIbotKLvvIzkuLrnvLrpkrHkurrono3otYTjgILmr5TlpoLpk7booYzvvIzogIHnmb7lp5Plj6/ku6XlrZjpkrHvvIzkvIHkuJrlj5HlsZXlj6/ku6XotLfmrL7vvIzpk7booYzlnKjlhbbkuK3otbfnnYDmoaXmooHjgIHkuK3ku4vlkozmnI3liqHkvZznlKjjgILmr5TlpoLkv53pmanvvIzlrp7pmYXkuIrmmK/kurrlnKjlgaXlurfjgIHlronlhajnmoTml7blgJnvvIznlKjkvZnpkrHmnaXkv53pmpznlr7nl4XjgIHmrbvkuqHnrYnmhI/lpJbkuovku7bnqoHlj5Hml7bnmoTmlZHmgKXpnIDmsYLvvIzmmK/kuIDkuKroh6rmiJHlubPooaHnmoTov4fnqIvvvIzlkIzml7bkuZ/og73kuLrkvIHkuJrono3otYTmj5DkvpvotYTph5HmnaXmupDjgILor4HliLjluILlnLrmm7TmmK/lpoLmraTvvIzogIHnmb7lp5PlhpLkuIDlrprpo47pmanmipXotYTotK3kubDogqHnpajvvIzlj5blvpfnmoTlm57miqXlj6/og73mmK/kvIHkuJrliKnmtqbliIbphY3vvIzkuZ/lj6/og73mmK/ogqHku7flt67ku7fvvIzmgLvlvZLmmK/lsIbkvZnpkrHnlKjkuo7nkIbotKLnmoTmoaXmooHjgILnp5/otYHkuZ/kuIDmoLfvvIzkvIHkuJrpgJrov4fnp5/otYHvvIzmiorkuIDmrKHmgKfnmoTlt6jpop3mipXotYTovazljJbkuLrplb/mnJ/nmoTnp5/otYHotLnnlKjlkozml6XluLjnmoTov5DooYzotYTph5HvvIzlsIbkuqfnlJ/mm7TlpJrnmoTmlYjnm4rvvIzotbfliLDono3otYTnmoTkvZznlKjjgILmgLvkuYvvvIzkuI3nrqHmmK/nm7TmjqXph5Hono3ns7vnu5/nmoTotYTmnKzluILlnLrlj5HooYzlgLrliLjnrYnvvIzov5jmmK/pl7TmjqXph5Hono3ns7vnu5/nmoTllYbkuJrpk7booYzmiJbpnZ7pk7booYzph5Hono3mnLrmnoTvvIzpg73mmK/lkITnp43nkIbotKLmlrnlvI/jgIHkuK3ku4vmlrnlvI/vvIzmnKzotKjkuIrmmK/kuLrmnInpkrHkurrnkIbotKLvvIzkuLrnvLrpkrHkurrono3otYTjgII8L3A+DQoNCiAgPHAgY2xhc3M9ImNvbnRlbnQiPuesrOS6jO+8jOS/oeeUqOOAgeS/oUqUqOOAgeS/oeeUqO+8jOadoOadhuOAgeadoOadhuOAgeadoOadhu+8jOmjjumZqeOAgemjjumZqeOAgemjjumZqeOAguS5i+aJgOS7peeeeOi/meenjemHjeWkjeeahOaWueW8j+i/m+ihjoY8uuiwg++8jOaYr+WboOS4uuKAnOS/oeeUqOKAneKAnOadoOadhuKAneKAnOmjjumZqeKAneWunuWcqOaYr+WkqumHjeimgeS6huOAgjwvcD4NCg0KICA8cCBjbGFzcz0iY29udGVudCI+6aaW5YWI77yM5L+h55So5piv6YeR6J6N55qE56uL6Lqr5LmL5pys77yM5piv6YeR6J6N55qE55Sf5ZG957q/44CC5L2T546w5Zyo5LiJ5Liq5pa56Z2i77ya6YeR6J6N5LyB5Lia5pys6Lqr6KaB5pyJ5L+h55So77yM5LiO6YeR6J6N5py65p6E5Y+R55Sf5YCf6LS35YWmo7O755qE5LyB5Lia6KaB5pyJ5L+h55So77yM5ZCE56eN6YeR6J6N5Lit5LuL5pyN5Yqh57G75LyB5Lia5Lmf6KaB5pyJ5L+h55So44CCPC9wPg0KDQogIDxwIGNsYXNzPSJjb250ZW50Ij7ooaHph4/kvIHkuJrnmoTkv6HnlKjvvIzopoHmiormj6Hlpb3kupTkuKrnu7TluqbjgILkuIDmmK/njrDph5HmtYHjgILnjrDph5HmtYHmr5TliKnmtqbmm7Tph43opoHjgILlpoLmnpzotYTph5Hpk77mlq3kuobvvIzkvIHkuJrltKnnm5jnoLTkuqfvvIzpooTmnJ/liKnmtqblho3pq5jkuZ/msqHmnInnlKjjgILmiYDku6XvvIzotYTmnKzluILlnLrkuIrogIPmoLjkvIHkuJrkv6HnlKjnmoTnrKzkuIDku7bkuovvvIzlsLHmmK/liIbmnpDkvIHkuJrotKLliqHmiqXooajnmoTnjrDph5HmtYHjgILkuozmmK/lm57miqXnjofjgILnnIvph43kvIHkuJrnmoTmiJDplb/pooTmnJ/vvIzpgJrov4fliIbmnpDmnKrmnaXlh6DlubTnmoTliKnmtqbjgIHluILnm4jnjofkuojku6XlhajpnaLooaHph4/jgILkuInmmK/mirXmirzmi4Xkv53jgILlpoLmnpznjrDph5HmtYHjgIHlm57miqXnjofml6Dms5XooaHph4/vvIzkvYbmnInmi4Xkv53lhazlj7jmiJbnrKzkuInmlrnkvIHkuJrmhL/mhI/mj5Dkvpvmi4Xkv53vvI
{'b': 'bd43298071fd1081bd4cb34', 'c': '9bf32f301f9bf31c7ff0a60', 'ct': 1659616576, 'pc': '88c3241079e45fb9g016c4e', 'ps': '88c3241079e45fb9g016c4e', 'r': 52374169, 'st': 0, 's': '88c4e66b'}
5D015EB1A0D9C42FE35D2F40D5A10717zpk7booYzkuZ/lj6/mlL7lv4PotLfmrL7jgILlm5vmmK/kvIHkuJrpq5jnrqHjgILkuIDkuKrlnLDmlrnkuYPoh7Plm73lhoXlpJbnn6XlkI3nmoTkvJjnp4DkvIHkuJrlrrbvvIzlhbflpIfnm7jlvZPpq5jlkKvph5Hph4/nmoTkuKrkurrkv6HnlKjvvIzkuqblj6/kuLrkvIHkuJrkv6HnlKjliqDliIbjgILkupTmmK/kvIHkuJrlk4HniYznrYnml6DlvaLotYTkuqfjgILov5nkupvml6DlvaLotYTkuqfkuZ/lupTnurPlhaXkv6HnlKjor4Tku7fkvZPns7vjgILov5nkupvpg73mmK/ph5Hono3op4TlvovvvIzlv4XpobvkuKXmoLzpgbXlvqrjgILnjrDlnKjluLjorrLlpKfmlbDmja7liIbmnpDvvIzkvYblpoLmnpzliIbmnpDnmoTnu5PmnpzmmK/kuI3pnIDopoHmnInnjrDph5HmtYHvvIzkuI3pnIDopoHotYTmnKzlm57miqXvvIzkuI3pnIDopoHmi4Xkv53nianvvIzov5nnp43ohLHnprvph5Hono3mnKzmupDnmoTliIbmnpDpg73mmK/igJzlgYflpKfnqbrigJ3nmoTjgILph5Hono3ooY3nlJ/lt6XlhbfkuZ/kuIDmoLfvvIzljbPkvr/np43nsbvnuYHlpJrvvIzkuZ/pg73lupTor6XlhbflpIfkv6HnlKjnmoTln7rmnKznibnlvoHvvIzlkKbliJnlsLHkvJrlr7zoh7Tph5Hono3ms6HmsqvjgII8L3A+DQoNCiAgPHAgY2xhc3M9ImNvbnRlbnQiPjIwMDjlubTlm73pmYXph5Hono3ljbHmnLrvvIzlsLHmmK/lhbjlnovnmoTkuI3mjInop4Tlvovlip7kuovjgILku6XllYblk4HmiL/kuLrku6PooajnmoTmrKHotLfkuqflk4Hlh7rkuobpl67popjvvIzpk7booYzkuI3mmK/mg7Plip7ms5XlnKjmirXmirzniankuIrlgZrmlofnq6DvvIzmiormrKHotLflj5jmiJDmraPluLjotLfmrL7vvIzogIzmmK/miormrKHotLfljZbliLDogqHnpajluILlnLrvvIzlj5jmiJDkuoZDRFPvvIjkv6HnlKjov53nuqbkupLmjaLvvInlgLrliLjvvIzmnaDmnYbmr5Tpq5jovr4x4oi2NDDjgILpm7fmm7zlhYTlvJ/lhazlj7g0MOS6v+e+juWFg+i0reS5sOS6hjEgNjAw5Lq/576O5YWDQ0RT5YC65Yi477yM5aaC5p6c5raoMTAl77yM5bCx6LWaMTYw5Lq/576O5YWD77yM5L2G5aaC5p6c6LeMMTAl77yM5bCx56uL5Y2z5bSp55uY44CC5oC75LmL77yM5LiA5YiH5rKh5pyJ5L+h55So55qE6YeR6J6N6YO95piv5YGH6YeR6J6N44CB5Lyq6YeR6J6N44CCPC9wPg0KDQogIDxwIGNsYXNzPSJjb250ZW50Ij7lhbbmrKHvvIzmnaDmnYbjgILkv6HnlKjmmK/mnaDmnYbnmoTln7rnoYDvvIzmnInkv6HnlKjmiY3mnInpgI/mlK/vvIzpgI/mlK/lsLHkvJrluKbmnaXmnaDmnYbmr5TjgILpk7booYznmoTlrZjotLfmr5TvvIzlrp7otKjmmK/kuIDnp43mnaDmnYbmr5TjgILlpoLmnpzkuIDlrrbpk7boOWzmnIkxMOS6v+WFg+i1hOacrO+8jOWPr+aUvui0tzEwMOS6v+WFg++8jOWwseaYrzHiiLYxMOeahOadoOadhuOAguenn+i1geWFrOWPuOaciTUw5Lq/5YWD6LWE5pys77yM5Y+v5Lul5pCeNTAw5Lq/5YWD56ef6LWB77yM5bCx5ZCM5qC35pivMeKItjEw55qE5p2g5p2G44CC5pCe5pyf6LSn5LiA6Iis5pivMeKItjIw55qE5p2g5p2G77yM6L+c5pyf5Lqk5piT5pivMeKItjXnmoTmnaDmnYbjgILogqHnpajluILlnLrmkJ7ono3otYTono3liLjvvIzlrp7otKjkuZ/mmK/or4HliLjlhazlj7jnu5nkuojmipXotYTkurrkuIDlrprmr5TkvovnmoTpgI/mlK/jgILmgLvkuYvvvIzmsqHmnInmnaDmnYbmr5TvvIzlpKflrrbkuIDmiYvkuqTpkrHjgIHkuIDmiYvkuqTotKfvvIzlsLHkuI3pnIDopoHkv6HnlKjvvIzkuZ/kuI3lrZjlnKjph5Hono3jgII8L3A+DQoNCiAgPHAgY2xhc3M9ImNvbnRlbnQiPuacgOWQju+8jOmjjumZqeOAguayoeacieadoOadhuavlOiwiOS4jeS4iumHkeieje+8jOS9huadoOadhuavlOi/h+mrmOWImeS8muS6p+eUn+mHkeiejemjjumZqe+8jOi/meaYr+i+qeivgeeahOWFs+ezu+OAguS4gOWIh+mHkeiejeWIm+aWsO+8jOmDveaYr+aDs+aWueiuvuazleaKiuadoOadhuavlOS4gOe6p+S4gOe6p+WcsOaUvuWkp+OAgui/h+mrmOeahOadoOadhuavlOaYr+S4gOWIh+Wdj+i0puOAgeS4gOWIh+mjjumZqeOAgeS4gOWIh+mHkeiejeWNseacuueahOadpea6kO+8jOWcqOS8geS4muWxgumdouihqOeOsOS4uuWdj+i0pu+8jOWcqOihjOS4muezu+e7n+WxgumdouaYr+mjjumZqe+8jOW7tuS8uOWIsOWbveWutuS5g+iHs+S4lueVjOWwseaIkOS6humHkeiejeWNseacuuOAguWUr+S4gOeahOino+WGs+WKnuazle+8jOWwseaYr+KAnOWOu+adoOadhuKAneOAguecn+ato+eahOaZuuaFp++8jOW6lOaYr+iuvuiuoeS4gOS4quS/oeeUqOWfuuehgOi+g+WlveOAgemjjumZqei+g+Wwj+eahOadoOadhuS9k+ezu++8jOi/meaYr+mHkeiejeeahOeyvumrk+OAgjwvcD4NCg0KICA8cCBjbGFzcz0iY29udGVudCI+5L+h55So44CB5p2g5p2G5ZKM6aOO6Zmp6L+Z5LiJ5Liq5pa56Z2i5Lmf5piv5LqS5Yqo55qE44CC5L+h55So5aW977yM5p2g5p2G5q+U5LiN6auY77yM6aOO6Zmp6Ieq54S25bCx5Lya5L2O44CC5p2g5p2G5q+U6auY77yM5L+h55So5YiZ5Lya6ZmN5L2O77yM6aOO6Zmp5Lmf5bCx6L6D6auY44CC5omA5pyJ55qE6YeR6J6N5Yib5paw77yM6YO95piv5Zu057uV6L+Z5LiJ5Liq5pa56Z2i5Zyo6L+Q6L2s77yM5YWz6ZSu6KaB5oqK5o+h5aW95YW25Lit55qE5bqm44CC5bC9566h6L+Z5Lqb5Z+65pys5Y6f55CG5piv6YeR6J6N6K++5aCC55qE5bi46K+G77yM5L2G5b+F6aG75b2T55yf57uP5p2l5b+177yM5LiN566h5piv6KGM6ZW/6L+Y5piv5Yqe5LqL5ZGY77yM6YO96KaB5aSp5aSp5b+144CB5pyI5pyI5b+144CB5bm05bm05b+177yM5Zug5Li65LiA5
{'b': 'bd43298071fd1081bd4cb34', 'c': '9bf32f301f9bf31c7ff0a60', 'ct': 1659616576, 'pc': '88c3241079e45fb9g016c4e', 'ps': '88c3241079e45fb9g016c4e', 'r': 63457156, 'st': 0, 's': '88c5387b'}
EB5FD2E55F8621E65A3B5E33EBC579C6PPD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiIHN0YW5kYWxvbmU9Im5vIj8+DQo8IURPQ1RZUEUgaHRtbCBQVUJMSUMgIi0vL1czQy8vRFREIFhIVE1MIDEuMS8vRU4iDQogICJodHRwOi8vd3d3LnczLm9yZy9UUi94aHRtbDExL0RURC94aHRtbDExLmR0ZCI+DQoNCjxodG1sIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hodG1sIj4NCjxoZWFkPg0KICA8dGl0bGU+PC90aXRsZT4NCiAgPGxpbmsgaHJlZj0iLi4vU3R5bGVzL3N0eWxlc2hlZXQuY3NzIiByZWw9InN0eWxlc2hlZXQiIHR5cGU9InRleHQvY3NzIiAvPg0KPC9oZWFkPg0KDQo8Ym9keT4NCiAgPGgyIGNsYXNzPSJzZWNvbmRUaXRsZSI+6YeR6J6N55qE5pys6LSoPC9oMj4NCg0KICA8cCBjbGFzcz0iY29udGVudCI+6YeR6J6N55qE5pys6LSo77yM5bCx5piv5LiJ5Y+l6K+d77ya5LiA5piv5Li65pyJ6ZKx5Lq655CG6LSi77yM5Li657y66ZKx5Lq66J6N6LWE77yb5LqM5piv6YeR6J6N5LyB5Lia55qE5qC45b+D6KaB5LmJ5bCx5Zyo5LqO5L+h55So44CB5p2g5p2G44CB6aOO6Zmp5LiJ5Liq546v6IqC77yM6KaB5oqK5o+h5aW95LiJ5Liq546v6IqC5ZKM5bqm77yb5LiJ5piv5LiA5YiH6YeR6J6N5rS75Yqo55qE55uu55qE5piv6KaB5Li65a6e5L2T57uP5rWO5pyN5Yqh44CC6L+Z5LiJ5Liq5pys6LSo54m55b6B77yM5LiN566h5piv5ZOq5Liq5bGC6Z2i55qE6YeR6J6N5LuO5Lia6ICF77yM6YO95bqU5pe25Yi76LCo6K6w5LqO5b+D44CCPC9wPg0KDQogIDxwIGNsYXNzPSJjb250ZW50Ij7nrKzkuIDvvIzkuLrmnInpkrHkurrnkIbotKLvvIzkuLrnvLrpkrHkurrono3otYTjgILmr5TlpoLpk7booYzvvIzogIHnmb7lp5Plj6/ku6XlrZjpkrHvvIzkvIHkuJrlj5HlsZXlj6/ku6XotLfmrL7vvIzpk7booYzlnKjlhbbkuK3otbfnnYDmoaXmooHjgIHkuK3ku4vlkozmnI3liqHkvZznlKjjgILmr5TlpoLkv53pmanvvIzlrp7pmYXkuIrmmK/kurrlnKjlgaXlurfjgIHlronlhajnmoTml7blgJnvvIznlKjkvZnpkrHmnaXkv53pmpznlr7nl4XjgIHmrbvkuqHnrYnmhI/lpJbkuovku7bnqoHlj5Hml7bnmoTmlZHmgKXpnIDmsYLvvIzmmK/kuIDkuKroh6rmiJHlubPooaHnmoTov4fnqIvvvIzlkIzml7bkuZ/og73kuLrkvIHkuJrono3otYTmj5DkvpvotYTph5HmnaXmupDjgILor4HliLjluILlnLrmm7TmmK/lpoLmraTvvIzogIHnmb7lp5PlhpLkuIDlrprpo47pmanmipXotYTotK3kubDogqHnpajvvIzlj5blvpfnmoTlm57miqXlj6/og73mmK/kvIHkuJrliKnmtqbliIbphY3vvIzkuZ/lj6/og73mmK/ogqHku7flt67ku7fvvIzmgLvlvZLmmK/lsIbkvZnpkrHnlKjkuo7nkIbotKLnmoTmoaXmooHjgILnp5/otYHkuZ/kuIDmoLfvvIzkvIHkuJrpgJrov4fnp5/otYHvvIzmiorkuIDmrKHmgKfnmoTlt6jpop3mipXotYTovazljJbkuLrplb/mnJ/nmoTnp5/otYHotLnnlKjlkozml6XluLjnmoTov5DooYzotYTph5HvvIzlsIbkuqfnlJ/mm7TlpJrnmoTmlYjnm4rvvIzotbfliLDono3otYTnmoTkvZznlKjjgILmgLvkuYvvvIzkuI3nrqHmmK/nm7TmjqXph5Hono3ns7vnu5/nmoTotYTmnKzluILlnLrlj5HooYzlgLrliLjnrYnvvIzov5jmmK/pl7TmjqXph5Hono3ns7vnu5/nmoTllYbkuJrpk7booYzmiJbpnZ7pk7booYzph5Hono3mnLrmnoTvvIzpg73mmK/lkITnp43nkIbotKLmlrnlvI/jgIHkuK3ku4vmlrnlvI/vvIzmnKzotKjkuIrmmK/kuLrmnInpkrHkurrnkIbotKLvvIzkuLrnvLrpkrHkurrono3otYTjgII8L3A+DQoNCiAgPHAgY2xhc3M9ImNvbnRlbnQiPuesrOS6jO+8jOS/oeeUqOOAgeS/oUqUqOOAgeS/oeeUqO+8jOadoOadhuOAgeadoOadhuOAgeadoOadhu+8jOmjjumZqeOAgemjjumZqeOAgemjjumZqeOAguS5i+aJgOS7peeeeOi/meenjemHjeWkjeeahOaWueW8j+i/m+ihjoY8uuiwg++8jOaYr+WboOS4uuKAnOS/oeeUqOKAneKAnOadoOadhuKAneKAnOmjjumZqeKAneWunuWcqOaYr+WkqumHjeimgeS6huOAgjwvcD4NCg0KICA8cCBjbGFzcz0iY29udGVudCI+6aaW5YWI77yM5L+h55So5piv6YeR6J6N55qE56uL6Lqr5LmL5pys77yM5piv6YeR6J6N55qE55Sf5ZG957q/44CC5L2T546w5Zyo5LiJ5Liq5pa56Z2i77ya6YeR6J6N5LyB5Lia5pys6Lqr6KaB5pyJ5L+h55So77yM5LiO6YeR6J6N5py65p6E5Y+R55Sf5YCf6LS35YWmo7O755qE5LyB5Lia6KaB5pyJ5L+h55So77yM5ZCE56eN6YeR6J6N5Lit5LuL5pyN5Yqh57G75LyB5Lia5Lmf6KaB5pyJ5L+h55So44CCPC9wPg0KDQogIDxwIGNsYXNzPSJjb250ZW50Ij7ooaHph4/kvIHkuJrnmoTkv6HnlKjvvIzopoHmiormj6Hlpb3kupTkuKrnu7TluqbjgILkuIDmmK/njrDph5HmtYHjgILnjrDph5HmtYHmr5TliKnmtqbmm7Tph43opoHjgILlpoLmnpzotYTph5Hpk77mlq3kuobvvIzkvIHkuJrltKnnm5jnoLTkuqfvvIzpooTmnJ/liKnmtqblho3pq5jkuZ/msqHmnInnlKjjgILmiYDku6XvvIzotYTmnKzluILlnLrkuIrogIPmoLjkvIHkuJrkv6HnlKjnmoTnrKzkuIDku7bkuovvvIzlsLHmmK/liIbmnpDkvIHkuJrotKLliqHmiqXooajnmoTnjrDph5HmtYHjgILkuozmmK/lm57miqXnjofjgILnnIvph43kvIHkuJrnmoTmiJDplb/pooTmnJ/vvIzpgJrov4fliIbmnpDmnKrmnaXlh6DlubTnmoTliKnmtqbjgIHluILnm4jnjofkuojku6XlhajpnaLooaHph4/jgILkuInmmK/mirXmirzmi4Xkv53jgILlpoLmnpznjrDph5HmtYHjgIHlm57miqXnjofml6Dms5XooaHph4/vvIzkvYbmnInmi4Xkv53lhazlj7jmiJbnrKzkuInmlrnkvIHkuJrmhL/mhI/mj5Dkvpvmi4Xkv53vvIzpk7booYzkuZ/lj6/mlL7lv4PotLfmrL7jgILlm5vmmK/kvIHkuJrpq5jnrqHjgILkuIDkuKrlnLDmlrnkuYPoh7Plm73lhoXlpJbnn6XlkI3nmoTkvJjnp4DkvIHkuJrlrrbvvIzlhbflpIfnm7jlvZPpq5jlkKvph5Hph4/nmoTkuKrkurrkv6HnlKjvvIzkuqblj6/kuLrkvIHkuJrkv6HnlKjliqDliIbjgILkupTmmK/kvIHkuJrlk4HniYznrYnml6DlvaLotYTkuqfjgILov5nkupvml6DlvaLotYTkuqfkuZ/lupTnurPlhaXkv6HnlKjor4Tku7fkvZPns7vjgILov5nkupvpg73mmK/ph5Hono3op4TlvovvvIzlv4XpobvkuKXmoLzpgbXlvqrjgILnjrDlnKjluLjorrLlpKfmlbDmja7liIbmnpDvvIzkvYblpoLmnpzliIbmnpDnmoTnu5PmnpzmmK/kuI3pnIDopoHmnInnjrDph5HmtYHvvIzkuI3pnIDopoHotYTmnKzlm57miqXvvIzkuI3pnIDopoHmi4Xkv53nianvvIzov5nnp43ohLHnprvph5Hono3mnKzmupDnmoTliIbmnpDpg73mmK/igJzlgYflpKfnqbrigJ3nmoTjgILph5Hono3ooY3nlJ/lt6XlhbfkuZ/kuIDmoLfvvIzljbPkvr/np43nsbvnuYHlpJrvvIzkuZ/pg73lupTor6XlhbflpIfkv6HnlKjnmoTln7rmnKznibnlvoHvvIzlkKbliJnlsLHkvJrlr7zoh7Tph5Hono3ms6HmsqvjgII8L3A+DQoNCiAgPHAgY2xhc3M9ImNvbnRlbnQiPjIwMDjlubTlm73pmYXph5Hono3ljbHmnLrvvIzlsLHmmK/lhbjlnovnmoTkuI3mjInop4Tlvovlip7kuovjgILku6XllYblk4HmiL/kuLrku6PooajnmoTmrKHotLfkuqflk4Hlh7rkuobpl67popjvvIzpk7booYzkuI3mmK/mg7Plip7ms5XlnKjmirXmirzniankuIrlgZrmlofnq6DvvIzmiormrKHotLflj5jmiJDmraPluLjotLfmrL7vvIzogIzmmK/miormrKHotLfljZbliLDogqHnpajluILlnLrvvIzlj5jmiJDkuoZDRFPvvIjkv6HnlKjov53nuqbkupLmjaLvvInlgLrliLjvvIzmnaDmnYbmr5Tpq5jovr4x4oi2NDDjgILpm7fmm7zlhYTlvJ/lhazlj7g0MOS6v+e+juWFg+i0reS5sOS6hjEgNjAw5Lq/576O5YWDQ0RT5YC65Yi477yM5aaC5p6c5raoMTAl77yM5bCx6LWaMTYw5Lq/576O5YWD77yM5L2G5aaC5p6c6LeMMTAl77yM5bCx56uL5Y2z5bSp55uY44CC5oC75LmL77yM5LiA5YiH5rKh5pyJ5L+h55So55qE6YeR6J6N6YO95piv5YGH6YeR6J6N44CB5Lyq6YeR6J6N44CCPC9wPg0KDQogIDxwIGNsYXNzPSJjb250ZW50Ij7lhbbmrKHvvIzmnaDmnYbjgILkv6HnlKjmmK/mnaDmnYbnmoTln7rnoYDvvIzmnInkv6HnlKjmiY3mnInpgI/mlK/vvIzpgI/mlK/lsLHkvJrluKbmnaXmnaDmnYbmr5TjgILpk7booYznmoTlrZjotLfmr5TvvIzlrp7otKjmmK/kuIDnp43mnaDmnYbmr5TjgILlpoLmnpzkuIDlrrbpk7boOWzmnIkxMOS6v+WFg+i1hOacrO+8jOWPr+aUvui0tzEwMOS6v+WFg++8jOWwseaYrzHiiLYxMOeahOadoOadhuOAguenn+i1geWFrOWPuOaciTUw5Lq/5YWD6LWE5pys77yM5Y+v5Lul5pCeNTAw5Lq/5YWD56ef6LWB77yM5bCx5ZCM5qC35pivMeKItjEw55qE5p2g5p2G44CC5pCe5pyf6LSn5LiA6Iis5pivMeKItjIw55qE5p2g5p2G77yM6L+c5pyf5Lqk5piT5pivMeKItjXnmoTmnaDmnYbjgILogqHnpajluILlnLrmkJ7ono3otYTono3liLjvvIzlrp7otKjkuZ/mmK/or4HliLjlhazlj7jnu5nkuojmipXotYTkurrkuIDlrprmr5TkvovnmoTpgI/mlK/jgILmgLvkuYvvvIzmsqHmnInmnaDmnYbmr5TvvIzlpKflrrbkuIDmiYvkuqTpkrHjgIHkuIDmiYvkuqTotKfvvIzlsLHkuI3pnIDopoHkv6HnlKjvvIzkuZ/kuI3lrZjlnKjph5Hono3jgII8L3A+DQoNCiAgPHAgY2xhc3M9ImNvbnRlbnQiPuacgOWQju+8jOmjjumZqeOAguayoeacieadoOadhuavlOiwiOS4jeS4iumHkeieje+8jOS9huadoOadhuavlOi/h+mrmOWImeS8muS6p+eUn+mHkeiejemjjumZqe+8jOi/meaYr+i+qeivgeeahOWFs+ezu+OAguS4gOWIh+mHkeiejeWIm+aWsO+8jOmDveaYr+aDs+aWueiuvuazleaKiuadoOadhuavlOS4gOe6p+S4gOe6p+WcsOaUvuWkp+OAgui/h+mrmOeahOadoOadhuavlOaYr+S4gOWIh+Wdj+i0puOAgeS4gOWIh+mjjumZqeOAgeS4gOWIh+mHkeiejeWNseacuueahOadpea6kO+8jOWcqOS8geS4muWxgumdouihqOeOsOS4uuWdj+i0pu+8jOWcqOihjOS4muezu+e7n+WxgumdouaYr+mjjumZqe+8jOW7tuS8uOWIsOWbveWutuS5g+iHs+S4lueVjOWwseaIkOS6humHkeiejeWNseacuuOAguWUr+S4gOeahOino+WGs+WKnuazle+8jOWwseaYr+KAnOWOu+adoOadhuKAneOAguecn+ato+eahOaZuuaFp++8jOW6lOaYr+iuvuiuoeS4gOS4quS/oeeUqOWfuuehgOi+g+WlveOAgemjjumZqei+g+Wwj+eahOadoOadhuS9k+ezu++8jOi/meaYr+mHkeiejeeahOeyvumrk+OAgjwvcD4NCg0KICA8cCBjbGFzcz0iY29udGVudCI+5L+h55So44CB5p2g5p2G5ZKM6aOO6Zmp6L+Z5LiJ5Liq5pa56Z2i5Lmf5piv5LqS5Yqo55qE44CC5L+h55So5aW977yM5p2g5p2G5q+U5LiN6auY77yM6aOO6Zmp6Ieq54S25bCx5Lya5L2O44CC5p2g5p2G5q+U6auY77yM5L+h55So5YiZ5Lya6ZmN5L2O77yM6aOO6Zmp5Lmf5bCx6L6D6auY44CC5omA5pyJ55qE6YeR6J6N5Yib5paw77yM6YO95piv5Zu057uV6L+Z5LiJ5Liq5pa56Z2i5Zyo6L+Q6L2s77yM5YWz6ZSu6KaB5oqK5o+h5aW95YW25Lit55qE5bqm44CC5bC9566h6L+Z5Lqb5Z+65pys5Y6f55CG5piv6YeR6J6N6K++5aCC55qE5bi46K+G77yM5L2G5b+F6aG75b2T55yf57uP5p2l5b+177yM5LiN566h5piv6KGM6ZW/6L+Y5piv5Yqe5LqL5ZGY77yM6YO96KaB5aSp5aSp5b+144CB5pyI5pyI5b+144CB5bm05bm05b+177yM5Zug5Li65LiA5YiH6YeR6J6N6aOO6Zmp6YO95piv6IOM56a75LqG6L+Z5Lqb5Z+65pys5Y6f55CG6ICM5Lqn55Sf55qE44CCPC9wPg0KDQogIDxwIGNsYXNzPSJjb250ZW50Ij7miYDku6XvvIzmiornjrDmnInkv6HnlKjnlKjotrPnlKjlpb3vvIzmnInkv6HnlKjkuI3lpb3lpb3lj5HmjKXlsLHmmK/mrbvlv4PnnLzvvIzkvYbmmK/mnInkv6HnlKjlsLHmiormnaDmnYbnlKjlvpfov4fkuoblpLTpgKDmiJDpo47pmanvvIzpgqPkuZ/mmK/nlq/lrZDmiJbogIXmmK/mhJrooKLnz5TkurrjgILph5Hono3nrqHnkIbnmoTopoHkuYnlsLHmmK/mioroh6rlt7Hov5nkuKrkvIHkuJrnmoTkv6HnlKjnlKjotrPvvIzkvYbmmK/nlKjotrPlsLHooajnjrDkuLrmnaDmnYbnmoTmlL7lpKfvvIzlnKjmlL7lpKfmnaDmnYbnmoTml7blgJnlj4jopoHmiorpo47pmanmjqfliLblnKjlupXnur/ph4zpnaLvvIzov5nlsLHmmK/kuIDkuKrpq5jmmI7nmoTph5Hono3pooblr7zkurrlkZjjgIHnrqHnkIbkurrlkZjjgIHlt6XkvZzkurrlkZjjgIHotKLkvJrkurrlkZjlv4Xpobvmi4XotJ/nmoTln7rmnKzotKPku7vjgII8L3A+DQoNCiAgPHAgY2xhc3M9ImNvbnRlbnQiPuesrOS4ie+8jOS4uuWunuS9k+e7j+a1juacjeWKoe+8jOi/meaYr+mHkeiejeeahOimgeS5ieOAguemu+W8gOWunuS9k+e7j+a1ju+8jOmHkeiejeWwseaYr+aXoOa6kOS5i+awtOOAgumCk+Wwj+W5s+WQjOW/lzE5OTHlubTop4blr5/mtabkuJzml7bosIjpgZPvvJrigJzph5Hono3lvojph43opoHvvIzph5Hono3mmK/njrDku6Pnu4/mtY7nmoTmoLjlv4PjgILmkJ7lpb3kuobvvIzkuIDnnYDmo4vmtLvvvIzlhajnm5jnmobmtLvjgILkuIrmtbfov4fljrvmmK/ph5Hono3kuK3lv4PvvIzmmK/otKfluIHoh6rnlLHlhZHmjaLnmoTlnLDmlrnvvIzku4rlkI7kuZ/opoHov5nmoLfmkJ7jgILkuK3lm73lnKjph5Hono3mlrnpnaLlj5blvpflm73pmYXlnLDkvY3vvIzpppblhYjopoHpnaDkuIrmtbfjgILigJ3njovlspDlsbHlkIzlv5fku7vlm73liqHpmaLlia/mgLvnkIbml7bmm77lvLrosIPvvIzigJznmb7kuJrlhbTvvIzliJnph5Hono3lhbTvvJvnmb7kuJrnqLPvvIzliJnph5Hono3nqLPigJ3vvIzov5nmmK/ph5Hono3ooYzkuJrnmoTph5Hnp5HnjonlvovjgILph5Hono3mmK/njrDku6Pnu4/mtY7nmoTmoLjlv4PvvIzlv4XpobvopoHkuLrlrp7kvZPnu4/mtY7mnI3liqHvvIzlkKbliJnlsLHkvJrlvILljJbkuLrigJzljaHmi4lPS+KAneOAgeiHquW8ueiHquWUseOAgjwvcD4NCg0KICA8cCBjbGFzcz0iY29udGVudCI+6L+Z5LiJ5Y+l6K+d6KGo546w5Zyo5a6P6KeC5LiK6Z2i77yM5Y2z5a6P6KeC57uP5rWO5Lit55qE6LSn5biB5L+h55So44CB6LSf5YC65L+h55So44CB5p2g5p2G5L+h55So5LuO5ZOq6YeM5p2l77yf5LiA5Liq5Zu95a62R0RQ55qE5aKe6ZW/546H44CB6LSi5pS/56iO5pS255qE5aKe6ZW/546H44CB5a6e5L2T57uP5rWO55qE5Yip5ram546H77yM5piv5LiA5YiH6LSn5biB5L+h55So44CB6LSf5YC65L+h55So44CB5p2g5p2G5L+h55So55qE5p2l5rqQ44CC5Y+N6L+H5p2l5p2g5p2G6L+H5aSn5Y+I5Lya5bim5p2l5a6P6KeC57uP5rWO55qE6aOO6Zmp44CC6L+Z5LiJ5Y+l6K+d6KGo546w5Zyo5b6u6KeC5LiK77yM5Y2z5q+P5Liq5LyB5Lia5a+56Ieq5bex55qE5YC65Yqh5p2g5p2G44CB5pWI55uK5pS55ZaE6YO95bqU5pel5pel5YWz5rOo44CB5pyI5pyI5YWz5rOo44CB5bm05bm05YWz5rOo77yM5oqK5LyB5Lia57uP6JCl5aW944CCPC9wPg0KDQogIDxwIGNsYXNzPSJjb250ZW50Ij7lnKjlhbfkvZPnmoTph5Hono3lt6XkvZzkuK3vvIzmiJHku6zlj6/ku6Xop4Llr5/liLDvvIzlt7Lnu4/ov5vlhaXmraPovajnmoTph5Hono3mnLrmnoTpg73mnInnnYDnrqHnkIbmnaDmnYbnmoTln7rmnKzliLbluqbvvIzmnInlpJrlpKfnmoTotYTmnKzmiY3og73mnInlpJrlpKfnmoTmnaDmnYbjgILkvovlpoLpk7booYzmnInkupTkuKrkv6HnlKjmjIfmoIfvvIzliIbliKvmmK/otYTmnKzlhYXotrPnjofjgIHotLfmrL7liKnmtqbnjofjgIHlnY/otKblh4blpIfph5HjgIHlrZjmrL7lh4blpIfph5HlkozlrZjotLfmr5TvvIzov5nkupvpg73mmK/pk7booYzkv6HnlKjnmoTln7rnoYDjgII8L3A+DQoNCiAgPHAgY2xhc3M9ImNvbnRlbnQiPuivgeWIuOWFrOWPuOS5n+Wlve+8jOWwj+i0t+WFrOWPuOS5n+Wlve+8jOS/nemZqeWFrOWPuOS5n+Wlve+8jOWHoeaYr+KAnOS4gOihjOS4pOS8muKAneaJueWHhueahOOAgeacieeJjOeFp+eahOmHkeiejeacuuaehO+8jOWFtuS/oeeUqOWfuuehgOOAgeadoOadhuavlOS+i+OAgemjjumZqemYsuiMg+mDveW/hemhu+acieWItuW6puWuieaOku+8jOacieaYjuehrueahOazleW+i+euoeWItuaIluiAheWItuW6pueuoeWItuOAguWcqOi/meaWuemdou+8jOS4gOS4qumHkeiejeW3peS9nOS6uuWRmOWPquimgeWtpuS5oOS6hui/meS6m+S4muWKoeW5tuW+quinhOi5iOefqe+8jOaKiuW3peS9nOWBmuWlveWwseWPr+S7peS6hu+8jOmZpOmdnumHkeiejeebkeeuoeWkseaOp+aJjeS8muS9v+S5seixoeS4m+eUn+OAguW6lOivpeivtO+8jOS4jeeuoeaYrzIw5LiW57qqODDlubTku6PjgIE5MOW5tOS7o++8jOi/mOaYrzIx5LiW57qq5Lul5ZCO77yM54m55Yir5pivMjAwOOW5tOS4lueVjOmHkeiejeWNseacuuS7peadpeeahOi/meWNgeW5tO+8jOmTtuihjOOAgeivgeWIuOOAgeS/nemZqeetieS8oOe7n+eahOOAgeW4uOinhOeahOmHkeiejeacuuaehOWFtuWunui/mOaYr+WfuuacrOinhOiMg+eahOOAgjwvcD4NCjwvYm9keT4NCjwvaHRtbD4NCg==
{'b': 'bd43298071fd1081bd4cb34', 'c': '9bf32f301f9bf31c7ff0a60', 'ct': 1659616577, 'pc': '88c3241079e45fb9g016c4e', 'ps': '88c3241079e45fb9g016c4e', 'r': 37636, 'st': 0, 's': 'ada6afaa'}
7D87040A12F560B15849F0E0EFC459DCYiH6YeR6J6N6aOO6Zmp6YO95piv6IOM56a75LqG6L+Z5Lqb5Z+65pys5Y6f55CG6ICM5Lqn55Sf55qE44CCPC9wPg0KDQogIDxwIGNsYXNzPSJjb250ZW50Ij7miYDku6XvvIzmiornjrDmnInkv6HnlKjnlKjotrPnlKjlpb3vvIzmnInkv6HnlKjkuI3lpb3lpb3lj5HmjKXlsLHmmK/mrbvlv4PnnLzvvIzkvYbmmK/mnInkv6HnlKjlsLHmiormnaDmnYbnlKjlvpfov4fkuoblpLTpgKDmiJDpo47pmanvvIzpgqPkuZ/mmK/nlq/lrZDmiJbogIXmmK/mhJrooKLnz5TkurrjgILph5Hono3nrqHnkIbnmoTopoHkuYnlsLHmmK/mioroh6rlt7Hov5nkuKrkvIHkuJrnmoTkv6HnlKjnlKjotrPvvIzkvYbmmK/nlKjotrPlsLHooajnjrDkuLrmnaDmnYbnmoTmlL7lpKfvvIzlnKjmlL7lpKfmnaDmnYbnmoTml7blgJnlj4jopoHmiorpo47pmanmjqfliLblnKjlupXnur/ph4zpnaLvvIzov5nlsLHmmK/kuIDkuKrpq5jmmI7nmoTph5Hono3pooblr7zkurrlkZjjgIHnrqHnkIbkurrlkZjjgIHlt6XkvZzkurrlkZjjgIHotKLkvJrkurrlkZjlv4Xpobvmi4XotJ/nmoTln7rmnKzotKPku7vjgII8L3A+DQoNCiAgPHAgY2xhc3M9ImNvbnRlbnQiPuesrOS4ie+8jOS4uuWunuS9k+e7j+a1juacjeWKoe+8jOi/meaYr+mHkeiejeeahOimgeS5ieOAguemu+W8gOWunuS9k+e7j+a1ju+8jOmHkeiejeWwseaYr+aXoOa6kOS5i+awtOOAgumCk+Wwj+W5s+WQjOW/lzE5OTHlubTop4blr5/mtabkuJzml7bosIjpgZPvvJrigJzph5Hono3lvojph43opoHvvIzph5Hono3mmK/njrDku6Pnu4/mtY7nmoTmoLjlv4PjgILmkJ7lpb3kuobvvIzkuIDnnYDmo4vmtLvvvIzlhajnm5jnmobmtLvjgILkuIrmtbfov4fljrvmmK/ph5Hono3kuK3lv4PvvIzmmK/otKfluIHoh6rnlLHlhZHmjaLnmoTlnLDmlrnvvIzku4rlkI7kuZ/opoHov5nmoLfmkJ7jgILkuK3lm73lnKjph5Hono3mlrnpnaLlj5blvpflm73pmYXlnLDkvY3vvIzpppblhYjopoHpnaDkuIrmtbfjgILigJ3njovlspDlsbHlkIzlv5fku7vlm73liqHpmaLlia/mgLvnkIbml7bmm77lvLrosIPvvIzigJznmb7kuJrlhbTvvIzliJnph5Hono3lhbTvvJvnmb7kuJrnqLPvvIzliJnph5Hono3nqLPigJ3vvIzov5nmmK/ph5Hono3ooYzkuJrnmoTph5Hnp5HnjonlvovjgILph5Hono3mmK/njrDku6Pnu4/mtY7nmoTmoLjlv4PvvIzlv4XpobvopoHkuLrlrp7kvZPnu4/mtY7mnI3liqHvvIzlkKbliJnlsLHkvJrlvILljJbkuLrigJzljaHmi4lPS+KAneOAgeiHquW8ueiHquWUseOAgjwvcD4NCg0KICA8cCBjbGFzcz0iY29udGVudCI+6L+Z5LiJ5Y+l6K+d6KGo546w5Zyo5a6P6KeC5LiK6Z2i77yM5Y2z5a6P6KeC57uP5rWO5Lit55qE6LSn5biB5L+h55So44CB6LSf5YC65L+h55So44CB5p2g5p2G5L+h55So5LuO5ZOq6YeM5p2l77yf5LiA5Liq5Zu95a62R0RQ55qE5aKe6ZW/546H44CB6LSi5pS/56iO5pS255qE5aKe6ZW/546H44CB5a6e5L2T57uP5rWO55qE5Yip5ram546H77yM5piv5LiA5YiH6LSn5biB5L+h55So44CB6LSf5YC65L+h55So44CB5p2g5p2G5L+h55So55qE5p2l5rqQ44CC5Y+N6L+H5p2l5p2g5p2G6L+H5aSn5Y+I5Lya5bim5p2l5a6P6KeC57uP5rWO55qE6aOO6Zmp44CC6L+Z5LiJ5Y+l6K+d6KGo546w5Zyo5b6u6KeC5LiK77yM5Y2z5q+P5Liq5LyB5Lia5a+56Ieq5bex55qE5YC65Yqh5p2g5p2G44CB5pWI55uK5pS55ZaE6YO95bqU5pel5pel5YWz5rOo44CB5pyI5pyI5YWz5rOo44CB5bm05bm05YWz5rOo77yM5oqK5LyB5Lia57uP6JCl5aW944CCPC9wPg0KDQogIDxwIGNsYXNzPSJjb250ZW50Ij7lnKjlhbfkvZPnmoTph5Hono3lt6XkvZzkuK3vvIzmiJHku6zlj6/ku6Xop4Llr5/liLDvvIzlt7Lnu4/ov5vlhaXmraPovajnmoTph5Hono3mnLrmnoTpg73mnInnnYDnrqHnkIbmnaDmnYbnmoTln7rmnKzliLbluqbvvIzmnInlpJrlpKfnmoTotYTmnKzmiY3og73mnInlpJrlpKfnmoTmnaDmnYbjgILkvovlpoLpk7booYzmnInkupTkuKrkv6HnlKjmjIfmoIfvvIzliIbliKvmmK/otYTmnKzlhYXotrPnjofjgIHotLfmrL7liKnmtqbnjofjgIHlnY/otKblh4blpIfph5HjgIHlrZjmrL7lh4blpIfph5HlkozlrZjotLfmr5TvvIzov5nkupvpg73mmK/pk7booYzkv6HnlKjnmoTln7rnoYDjgII8L3A+DQoNCiAgPHAgY2xhc3M9ImNvbnRlbnQiPuivgeWIuOWFrOWPuOS5n+Wlve+8jOWwj+i0t+WFrOWPuOS5n+Wlve+8jOS/nemZqeWFrOWPuOS5n+Wlve+8jOWHoeaYr+KAnOS4gOihjOS4pOS8muKAneaJueWHhueahOOAgeacieeJjOeFp+eahOmHkeiejeacuuaehO+8jOWFtuS/oeeUqOWfuuehgOOAgeadoOadhuavlOS+i+OAgemjjumZqemYsuiMg+mDveW/hemhu+acieWItuW6puWuieaOku+8jOacieaYjuehrueahOazleW+i+euoeWItuaIluiAheWItuW6pueuoeWItuOAguWcqOi/meaWuemdou+8jOS4gOS4qumHkeiejeW3peS9nOS6uuWRmOWPquimgeWtpuS5oOS6hui/meS6m+S4muWKoeW5tuW+quinhOi5iOefqe+8jOaKiuW3peS9nOWBmuWlveWwseWPr+S7peS6hu+8jOmZpOmdnumHkeiejeebkeeuoeWkseaOp+aJjeS8muS9v+S5seixoeS4m+eUn+OAguW6lOivpeivtO+8jOS4jeeuoeaYrzIw5LiW57qqODDlubTku6PjgIE5MOW5tOS7o++8jOi/mOaYrzIx5LiW57qq5Lul5ZCO77yM54m55Yir5pivMjAwOOW5tOS4lueVjOmHkeiejeWNseacuuS7peadpeeahOi/meWNgeW5tO+8jOmTtuihjOOAgeivgeWIuOOAgeS/nemZqeetieS8oOe7n+eahOOAgeW4uOinhOeahOmHkeiejeacuuaehOWFtuWunui/mOaYr+WfuuacrOinhOiMg+eahOOAgjwvcD4NCjwvYm9keT4NCjwvaHRtbD4NCg==
 @
  AO<?xml version="1.0" encoding="utf-8" standalone="no"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN"
  "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">

<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <title></title>
  <link href="../Styles/stylesheet.css" rel="stylesheet" type="text/css" />
</head>

<body>
  <h2 class="secondTitle">金融的本质</h2>

  <p class="content">金融的本质，就是三句话：一是为有钱人理财，为缺钱人融资；二是金融企业的核心要义就在于信用、杠杆、风险三个环节，要把握好三个环节和度；三是一切金融活动的目的是要为实 
体经济服务。这三个本质特征，不管是哪个层面的金融从业者，都应时刻谨记于心。</p>

  <p class="content">第一，为有钱人理财，为缺钱人融资。比如银行，老百姓可以存钱，企业发展可以贷款，银行在其中起着桥梁、中介和服务作用。比如保险，实际上是人在健康、安全的时候，用余钱来 
保障疾病、死亡等意外事件突发时的救急需求，是一个自我平衡的过程，同时也能为企业融资提供资金来源。证券市场更是如此，老百姓冒一定风险投资购买股票，取得的回报可能是企业利润分配，也可能是股
价差价，总归是将余钱用于理财的桥梁。租赁也一样，企业通过租赁，把一次性的巨额投资转化为长期的租赁费用和日常的运行资金，将产生更多的效益，起到融资的作用。总之，不管是直接金融系统的资本市
场发行债券等，还是间接金融系统的商业银行或非银行金融机构，都是各种理财方式、中介方式，本质上是为有钱人理财，为缺钱人融资。</p>

  <p c!ss="content">第二，用、信J、信用，杢v、杠杆、杠杆，风险、风险、风险。之所以x这种重复的方式进衎<调，是因为“信用”“杠杆”“风险”实在是太重要了。</p>

  <p class="content">首先，信用是金融的立身之本，是金融的生命线。体现在三个方面：金融企业本身要有俣+，与金融机构发生借贷兦的企业要有信用，各种金融中介服务类企业也要有信用。</p>        

  <p class="content">衡量企业的信用，要把握好五个维度。一是现金流。现金流比利润更重要。如果资金链断了，企业崩盘破产，预期利润再高也没有用。所以，资本市场上考核企业信用的第一件事，就是 
分析企业财务报表的现金流。二是回报率。看重企业的成长预期，通过分析未来几年的利润、市盈率予以全面衡量。三是抵押担保。如果现金流、回报率无法衡量，但有担保公司或第三方企业愿意提供担保－@
];׼银行也可放心贷款。四是企业高管。一个地方乃至国内外知名的优秀企业家，具备相当高含金量的个人信用，亦可为企业信用加分。五是企业品牌等无形资产。这些无形资产也应纳入信用评价体系。这些都 
是金融规律，必须严格遵循。现在常讲大数据分析，但如果分析的结果是不需要有现金流，不需要资本回报，不需要担保物，这种脱离金融本源的分析都是“假大空”的。金融衍生工具也一样，即便种类繁多，也
都应该具备信用的基本特征，否则就会导致金融泡沫。</p>

  <p class="content">2008年国际金融危机，就是典型的不按规律办事。以商品房为代表的次贷产品出了问题，银行不是想办法在抵押物上做文章，把次贷变成正常贷款，而是把次贷卖到股票市场，变成了CDS（信用违约互换）债券，杠杆比高达1∶40。雷曼兄弟公司40亿美元购买了1 600亿美元CDS债券，如果涨10%，就赚160亿美元，但如果跌10%，就立即崩盘。总之，一切没有信用的金融都是假金融、伪金融。</p> 

  <p class="content">其次，9杆。信用是杠杆的基础，有信用才有透支，透支就会带来杠杆比。银行的存贷比，实质是一种杠杆比。如果一家银9l有10亿元资本，可放贷100亿元，就是1∶10的杠杆。租赁公司 
有50亿元资本，可以搞500亿元租赁，就同样是1∶10的杠杆。搞期货一般是1∶20的杠杆，远期交易是1∶5的杠杆。股票市场搞融资融券，实质也是证券公司给予投资人一定比例的透支。总之，没有杠杆比，大家一
手交钱、一手交货，就不需要信用，也不存在金融。</p>

  <p class="content">最后，风险。没有杠杆比谈不上金融，但杠杆比过高则会产生金融风险，这是辩证的关系。一切金融创新，都是想方设法把杠杆比一级一级地放大。过高的杠杆比是一切坏账、一切风险 
、一切金融危机的来源，在企业层面表现为坏账，在行业系统层面是风险，延伸到国家乃至世界就成了金融危机。唯一的解决办法，就是“去杠杆”。真正的智慧，应是设计一个信用基础较好、风险较小的杠杆体
系，这是金融的精髓。</p>

  <p class="content">信用、杠杆和风险这三个方面也是互动的。信用好，杠杆比不高，风险自然就会低。杠杆比高，信用则会降低，风险也就较高。所有的金融创新，都是围绕这三个方面在运转，关键要把 
握好其中的度。尽管这些基本原理是金融课堂的常识，但必须当真经来念，不管是行长还是办事员，都要天天念、月月念、年年念，因为一]ABC 金融风险都是背离了这些基本原理而产生的。</p>

  <p class="content">所以，把现有信用用足用好，有信用不好好发懕就是死心眼，但是有信用就把杠杆用得过了头造成风险，那也是疯子或者是愚蠢ϔ人。金融管理的要义就是把自己这个企业的信用用足，但
是用足就表现为杠杆的放大，在放大杠杆的时候又要把风险控制在底线里面，这就是一个高明的金融领导人员、管理人员、工作人员、财会人员必须担负的基本责任。</p>

  <p class="content">第三，为实体经济服务，这是金融的要义。离开实体经济，金融就是无源之水。邓小平同志1991年视察浦东时谈道：“金融很重要，金融是现代经济的核心。搞好了，一着棋活，全盘皆活
。上海过去是金融中心，是货币自由兑换的地方，今后也要这样搞。中国在金融方面取得国际地位，首先要靠上海。”王岐山同志任国务院副总理时曾强调，“百业兴，则金融兴；百业稳，则金融稳”，这是金融 
行业的金科玉律。金融是现代经济的核心，必须要为实体经济服务，否则就会异化为“卡拉OK”、自弹自唱。</p>

  <p class="content">这三句话表现在宏观上面，即宏观经济中的货币信用、负债信用、杠杆信用从哪里来？一个国家GDP的增长率、财政税收的增长率、实体经济的利润率，是一切货币信用、负债信用、杠杆
信用的来源。反过来杠杆过大又会带来宏观经济的风险。这三句话表现在微观上，即每个企业对自己的债务杠杆、效益改善都应日日关注、月月关注、年年关注，把企业经营好。</p>

  <p class="content">在具体的金融工作中，我们可以观察到，已经进入正轨的金融机构都有着管理杠杆的基本制度，有多大的资本才能有多大的杠杆。例如银行有五个信用指标，分别是资本充足率、贷款利 
润率、坏账准备金、存款准备金和存贷比，这些都是银行信用的基础。</p>

  <p class="content">证券公司也好，小贷公司也好，保险公司也好，凡是“一行两会”批准的、有牌照的金融机构，其信用基础、杠杆比例、风险防范都必须有制度安排，有明确的法律管制或者制度管制。在 
这方面，一个金融工作人员只要学习了这些业务并循规蹈矩，把工作做好就可以了，除非金融监管失控才会使乱象丛生。应该说，不管是20世纪80年代、90年代，还是21世纪以后，特别是2008年世界金融危机以
来的这十年，银行、证券、保险等传统的、常规的金融机构其实还是基本规范的。</p>
</body>
</html>
```