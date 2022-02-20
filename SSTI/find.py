import json

a = """

"""

num = 0
allList = []

result = ""
for i in a:
    if i == ">":
        result += i
        allList.append(result)
        result = ""
    elif i == "\n" or i == ",":
        continue
    else:
        result += i

for k, v in enumerate(allList):
    if "warnings.catch_warnings" in v:
        print(str(k) + "--->" + v)