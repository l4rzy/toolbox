import pycurl
import json

c = pycurl.Curl()
c.setopt(c.URL, "http://localhost:5058/tunnel")
c.setopt(
    pycurl.USERAGENT,
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
)
headers = ["Accept:application/json", "Content-Type:application/json"]

c.setopt(pycurl.HTTPHEADER, headers)
post_data = {"url": "http://google.com", "headers": ["hello: world"]}
datas = json.dumps(post_data)
# Form data must be provided already urlencoded.
# postfields = urlencode(post_data)
print(datas)
# Sets request method to POST,
# Content-Type header to application/x-www-form-urlencoded
# and data to send in request body.
c.setopt(c.POSTFIELDS, "{\"url\":\"google.com\",\"headers\":[\"xyz: bac\"]}")

c.perform()
c.close()
